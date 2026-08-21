import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { CallId, createUserMessage } from '@deepseek-ai/dsh-llm'
import SessionStore, { Session, SessionId, type SessionEvent } from '@deepseek-ai/dsh-session'
import type { Agent } from '@deepseek-ai/dsh-agent'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import { defineTool } from '@deepseek-ai/dsh-tools'
import Investigation, {
  BOTH_LAN_CONVERSATION_REASON, CDN_C2_REASON, CHASSIS_CLOSED_MEANS, CHASSIS_MISSION_PURPOSE,
  CLOSE_FILE_REASON, Config, foldActions, foldExtras,
  foldHunts, foldIdentities, foldMission, foldPlan, foldReport, METHODOLOGY_SECTION,
  MISSION_PURPOSE_REASON, PLAN_ALTERNATIVE_REASON, PLAN_C2_HYPOTHESIS_REASON,
  PLAN_INVENTORY_REASON, requireCaseReport, resolveCaseDir,
  setsWhoWhere,
} from '../src/index.ts'
import { stampReadyMindset } from './mindset-fixture.ts'

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

async function setup(
  over: Partial<ConstructorParameters<typeof Investigation>[1]> = {},
  opts: { mindset?: boolean } = {},
): Promise<{
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
  ctx.tools.register(defineTool({
    name: 'edit',
    description: 'Edit stand-in.',
    parameters: { file_path: { type: 'string', required: true } },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true } } },
      render: () => [{ type: 'text', text: 'edited' }],
    },
    execute: () => Promise.resolve({ ok: true }),
  }))
  const owner = agent()
  if (opts.mindset !== false) stampReadyMindset(ctx.investigation, owner.session)
  return { ctx, caseDir: root, owner }
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
    const emptyStamp = {
      type: 'investigation/identity' as const,
      seq: 1,
      time: 0,
      data: { kind: 'mac' as const, value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '' },
    }
    const filledStamp = {
      type: 'investigation/identity' as const,
      seq: 2,
      time: 0,
      data: { kind: 'mac' as const, value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
    }
    expect(foldIdentities([emptyStamp, filledStamp])).toEqual([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
    ])
    expect(foldIdentities([filledStamp, {
      ...emptyStamp,
      data: { ...emptyStamp.data, evidence_id: '10.0.10.3' },
    }])).toEqual([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
    ])
    const dcStamp = {
      type: 'investigation/identity' as const,
      seq: 1,
      time: 0,
      data: { kind: 'mac' as const, value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.3' },
    }
    const bindEvent = {
      type: 'investigation/bind' as const,
      seq: 3,
      time: 0,
      data: relationshipBind,
    }
    expect(foldIdentities([dcStamp, filledStamp, bindEvent])).toEqual([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
    ])
    expect(foldIdentities([filledStamp, dcStamp, bindEvent])).toEqual([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
    ])
    const hostDc = {
      type: 'investigation/identity' as const,
      seq: 1,
      time: 0,
      data: { kind: 'hostname' as const, value: 'lan-host', label: 'hostname', evidence_id: '10.0.10.3' },
    }
    const hostVictim = {
      type: 'investigation/identity' as const,
      seq: 2,
      time: 0,
      data: { kind: 'hostname' as const, value: 'lan-host', label: 'hostname', evidence_id: '10.0.10.2' },
    }
    expect(foldIdentities([hostDc, hostVictim, bindEvent])).toEqual([
      { kind: 'hostname', value: 'lan-host', label: 'hostname', evidence_id: '10.0.10.3' },
    ])
    const talking = {
      type: 'tool/result' as const,
      seq: 0,
      time: 0,
      data: {
        turn: 1,
        step: 1,
        message: {
          content: [{
            type: 'tool-result' as const,
            toolCallId: 'conv-1',
            content: [{ type: 'text' as const, text: '10.0.10.2 → 198.51.100.80 TCP' }],
          }],
        },
      },
    } as SessionEvent
    expect(foldIdentities([dcStamp, filledStamp, talking])).toEqual([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
    ])
    const noVictimBind = {
      type: 'investigation/bind' as const,
      seq: 3,
      time: 0,
      data: { relationship: relationshipBind.relationship, endpoints: [] },
    }
    expect(foldIdentities([dcStamp, filledStamp, noVictimBind])).toEqual([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.3' },
    ])
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
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
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
    const { ctx, owner } = await setup({}, { mindset: false })
    const empty = await ctx.systemPrompt.assemble({ agent: owner })
    expect(empty.sections.some(section => section.name === 'investigation:policy' && section.text === METHODOLOGY_SECTION)).toBe(true)
    expect(METHODOLOGY_SECTION).toContain('Before Who/Where, bind the conversation.')
    expect(METHODOLOGY_SECTION).toContain(
      'Mission, Plan, Action, and Report wrap Observation, then Question, then Hypothesis, then Answer, then Bind, then Who/Where.',
    )
    expect(METHODOLOGY_SECTION).toContain(
      'The chassis stamps Mission as a victim-identity + C2 investigation.',
    )
    expect(METHODOLOGY_SECTION).toContain(
      'The cited conversation must include a cue/observation address. Role c2 cannot be a LAN address or a well-known CDN or update destination.',
    )
    expect(ctx.tools.get('bind_relationship')).toBeDefined()
    expect(ctx.tools.get('investigation_mission')?.presentCall?.({
      purpose: 'Scope an identity+C2 case',
      cue_addr: '198.51.100.80',
      cue_evidence_id: 'conv-1',
      cue_validation: 'valid',
    })?.title).toBe('Mission')
    expect(ctx.tools.get('investigation_plan')?.presentCall?.({
      inventory: ['evidence/a.pcap'],
    })?.title).toBe('Plan')
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
    stampReadyMindset(ctx.investigation, owner.session)
    const withPlan = await ctx.systemPrompt.assemble({ agent: owner })
    expect(withPlan.contexts.find(entry => entry.name === 'investigation:ledger')?.text).toContain('Mission:')
    expect(withPlan.contexts.find(entry => entry.name === 'investigation:ledger')?.text).toContain('Plan:')
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
        if (filter.includes('llmnr')) {
          return Promise.resolve({ text: 'hostname: lan-host\tip.addr: 10.0.10.2' })
        }
        if (filter.includes('kerberos.CNameString')) {
          return Promise.reject(new Error('tshark missing'))
        }
        return Promise.resolve('samr dump' as unknown as { text: string })
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
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
    ])
    expect(ctx.investigation.identities(owner.session).filter(item => item.kind === 'hostname')).toEqual([
      { kind: 'hostname', value: 'lan-host', label: 'hostname', evidence_id: '10.0.10.2' },
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

  it('stamps hunt-subject evidence_id from a scoped pcap_filter display filter', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
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
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter.includes('ip.src ==')) return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:0a' })
        if (filter.includes('tls.handshake.extensions_server_name')) {
          return Promise.resolve({ text: 'tls.handshake.extensions_server_name: c2.example.test' })
        }
        if (filter.includes('ip.addr ==')) return Promise.resolve({ text: 'hostname: lan-host' })
        if (filter.includes('eth.src')) return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:0c' })
        if (filter.includes('llmnr')) return Promise.resolve({ text: 'hostname: other-host' })
        return Promise.resolve({ text: 'tcp' })
      },
    }))
    const mac = await ctx.tools.execute({
      signal,
      callId: CallId('pcap-eth-scoped'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: '(eth.src) and ip.src == 10.0.10.2',
        fields: ['eth.src'],
      },
      agent: owner,
    })
    expect(mac.isError).toBe(false)
    const host = await ctx.tools.execute({
      signal,
      callId: CallId('pcap-name-scoped'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: '(llmnr or nbns or browser) and ip.addr == 10.0.10.2',
      },
      agent: owner,
    })
    expect(host.isError).toBe(false)
    await ctx.tools.execute({
      signal,
      callId: CallId('pcap-eth-unscoped'),
      name: 'pcap_filter',
      arguments: { path: 'evidence/a.pcap', display_filter: 'eth.src', fields: ['eth.src'] },
      agent: owner,
    })
    await ctx.tools.execute({
      signal,
      callId: CallId('pcap-name-unscoped'),
      name: 'pcap_filter',
      arguments: { path: 'evidence/a.pcap', display_filter: 'llmnr or nbns or browser' },
      agent: owner,
    })
    await ctx.tools.execute({
      signal,
      callId: CallId('pcap-tcp'),
      name: 'pcap_filter',
      arguments: { path: 'evidence/a.pcap', display_filter: 'tcp' },
      agent: owner,
    })
    const domain = await ctx.tools.execute({
      signal,
      callId: CallId('pcap-c2-domain-scoped'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter:
          '(tls.handshake.extensions_server_name or dns.qry.name or dns.resp.name) and ip.addr == 198.51.100.80',
        fields: [
          'tls.handshake.extensions_server_name',
          'dns.qry.name',
          'dns.resp.name',
        ],
      },
      agent: owner,
    })
    expect(domain.isError).toBe(false)
    expect(ctx.investigation.identities(owner.session)).toEqual(expect.arrayContaining([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
      { kind: 'hostname', value: 'lan-host', label: 'hostname', evidence_id: '10.0.10.2' },
      { kind: 'mac', value: '02:00:00:00:00:0c', label: 'MAC' },
      { kind: 'hostname', value: 'other-host', label: 'hostname' },
      { kind: 'hostname', value: 'c2.example.test', label: 'hostname', evidence_id: '198.51.100.80' },
    ]))
  })

  it('restamps a missing MAC evidence_id from a later victim-IP-scoped eth.src dump', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '',
    })
    expect(ctx.investigation.recordIdentity(owner.session, {
      kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC',
    })).toBe(false)
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
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter.includes('ip.src == 10.0.10.2') || filter.includes('ip.addr == 10.0.10.2')) {
          return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:0a' })
        }
        if (filter.includes('ip.src == 10.0.10.3') || filter.includes('ip.addr == 10.0.10.3')) {
          return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:0b' })
        }
        return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:0c' })
      },
    }))
    const victimDump = await ctx.tools.execute({
      signal,
      callId: CallId('pcap-eth-victim-restamp'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: '(eth.src) and ip.src == 10.0.10.2',
        fields: ['eth.src'],
      },
      agent: owner,
    })
    expect(victimDump.isError).toBe(false)
    const dcDump = await ctx.tools.execute({
      signal,
      callId: CallId('pcap-eth-dc-restamp'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: '(eth.src) and ip.addr == 10.0.10.3',
        fields: ['eth.src'],
      },
      agent: owner,
    })
    expect(dcDump.isError).toBe(false)
    expect(ctx.investigation.identities(owner.session).filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' },
      { kind: 'mac', value: '02:00:00:00:00:0b', label: 'MAC', evidence_id: '10.0.10.3' },
    ])
    expect(ctx.investigation.recordIdentity(owner.session, {
      kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.3',
    })).toBe(false)
    expect(ctx.investigation.identities(owner.session).find(item => item.value === '02:00:00:00:00:0a'))
      .toEqual({ kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' })
  })

  it('overwrites a DC-stamped MAC from a later victim-IP-scoped eth.src dump', async () => {
    const { ctx, caseDir, owner } = await setup({ autoHunt: false })
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    ctx.investigation.recordBind(owner.session, {
      relationship: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
      },
      endpoints: [
        { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' },
        { addr: '198.51.100.80', role: 'c2', because: 'cue' },
      ],
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.3',
    })
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
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter.includes('ip.src == 10.0.10.2') || filter.includes('ip.addr == 10.0.10.2')) {
          return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:0a' })
        }
        if (filter.includes('ip.src == 10.0.10.3') || filter.includes('ip.addr == 10.0.10.3')) {
          return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:0a' })
        }
        return Promise.resolve({ text: 'eth.src: 02:00:00:00:00:0c' })
      },
    }))
    const victimDump = await ctx.tools.execute({
      signal,
      callId: CallId('pcap-eth-victim-overwrite'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: '(eth.src) and ip.src == 10.0.10.2',
        fields: ['eth.src'],
      },
      agent: owner,
    })
    expect(victimDump.isError).toBe(false)
    expect(ctx.investigation.identities(owner.session).find(item => item.value === '02:00:00:00:00:0a'))
      .toEqual({ kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' })
    const dcDump = await ctx.tools.execute({
      signal,
      callId: CallId('pcap-eth-dc-no-overwrite'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: '(eth.src) and ip.addr == 10.0.10.3',
        fields: ['eth.src'],
      },
      agent: owner,
    })
    expect(dcDump.isError).toBe(false)
    expect(ctx.investigation.identities(owner.session).find(item => item.value === '02:00:00:00:00:0a'))
      .toEqual({ kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' })
    expect(ctx.investigation.recordIdentity(owner.session, {
      kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.3',
    })).toBe(false)
    expect(ctx.investigation.identities(owner.session).find(item => item.value === '02:00:00:00:00:0a'))
      .toEqual({ kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', evidence_id: '10.0.10.2' })
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
    const { ctx, caseDir, owner } = await setup()
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
    const noVictim = await ctx.tools.execute({
      signal,
      callId: CallId('bind-no-victim'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'unknown', because: 'not yet' }],
      },
      agent: owner,
    })
    expect(noVictim.isError).toBe(true)
    expect(noVictim.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'bind_relationship requires exactly one victim',
    )
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'other-end')).toBe(false)
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
    const flipText = flip.content.map(block => 'text' in block ? block.text : '').join('')
    expect(flipText).toContain('unbound: hunt LAN ip.src talking to 198.51.100.80 (ip.dst == 198.51.100.80).')
    expect(flipText).not.toContain('unbound: assign victim vs c2 on the cited conversation.')
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'other-end', subjectKind: 'ip', subject: '198.51.100.80',
    })
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
    const citedFlip = await ctx.tools.execute({
      signal,
      callId: CallId('bind-cited-flip'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'conv-1',
        endpoints: [{
          addr: '198.51.100.80',
          role: 'victim',
          because: '10.0.10.2 talking to 198.51.100.80 in evidence conv-1 dport 443',
        }],
      },
      agent: owner,
    })
    expect(citedFlip.isError).toBe(true)
    expect(citedFlip.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'unbound: hunt LAN ip.src talking to 198.51.100.80 (ip.dst == 198.51.100.80).',
    )
    expect(ctx.investigation.hunts(owner.session).filter(hunt => hunt.kind === 'other-end')).toHaveLength(1)
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
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
    const wroteClose = await ctx.tools.execute({
      signal,
      callId: CallId('write-report'),
      name: 'write',
      arguments: { file_path: join(caseDir, 'report.md') },
      agent: owner,
    })
    expect(wroteClose.isError).toBe(true)
    expect(wroteClose.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      CLOSE_FILE_REASON,
    )
    const editedClose = await ctx.tools.execute({
      signal,
      callId: CallId('edit-report'),
      name: 'edit',
      arguments: { file_path: join(caseDir, 'report.md') },
      agent: owner,
    })
    expect(editedClose.isError).toBe(true)
    expect(editedClose.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      CLOSE_FILE_REASON,
    )
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

  it('coerces stringified endpoints and dport through bind_relationship execute', async () => {
    const { ctx, owner } = await setup()
    const endpoints = [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }]
    const native = await ctx.tools.execute({
      signal,
      callId: CallId('bind-native'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints,
      },
      agent: owner,
    })
    expect(native.isError).toBe(false)
    const expected = ctx.investigation.bind(owner.session)
    const other = await setup()
    const coerced = await other.ctx.tools.execute({
      signal,
      callId: CallId('bind-stringified'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: '443', t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: JSON.stringify(endpoints),
      },
      agent: other.owner,
    })
    expect(coerced.isError).toBe(false)
    expect(coerced.content.map(block => 'text' in block ? block.text : '').join('')).not.toContain('INVALID_ARGS')
    expect(other.ctx.investigation.bind(other.owner.session)).toEqual(expected)
    const cue = await other.ctx.tools.execute({
      signal,
      callId: CallId('bind-stringified-cue'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: '443', t: 't', evidence_id: 'conv-1',
        endpoints: JSON.stringify([{ addr: '198.51.100.80', role: 'victim', because: 'the alert named this IP' }]),
      },
      agent: other.owner,
    })
    expect(cue.isError).toBe(true)
    expect(cue.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'unbound: hunt LAN ip.src talking to 198.51.100.80 (ip.dst == 198.51.100.80).',
    )
    const notArray = await other.ctx.tools.execute({
      signal,
      callId: CallId('bind-not-array'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'conv-1',
        endpoints: 'not-a-json-array',
      },
      agent: other.owner,
    })
    expect(notArray.isError).toBe(true)
    expect(notArray.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'bind_relationship endpoints must be an array',
    )
    const missing = await other.ctx.tools.execute({
      signal,
      callId: CallId('bind-missing-dport'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', t: 't', evidence_id: 'conv-1',
        endpoints,
      },
      agent: other.owner,
    })
    expect(missing.isError).toBe(true)
    const zero = await other.ctx.tools.execute({
      signal,
      callId: CallId('bind-dport-zero'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: '0', t: 't', evidence_id: 'conv-1',
        endpoints,
      },
      agent: other.owner,
    })
    expect(zero.isError).toBe(true)
    const high = await other.ctx.tools.execute({
      signal,
      callId: CallId('bind-dport-high'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: '65536', t: 't', evidence_id: 'conv-1',
        endpoints,
      },
      agent: other.owner,
    })
    expect(high.isError).toBe(true)
  })

  it('denies a both-LAN bind_relationship and does not issue other-end', async () => {
    const { ctx, owner } = await setup()
    const dc = await ctx.tools.execute({
      signal,
      callId: CallId('bind-dc'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '10.0.10.3', dport: 88, t: 't', evidence_id: 'conv-dc',
        endpoints: [
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 10.0.10.3' },
          { addr: '10.0.10.3', role: 'c2', because: '10.0.10.2 talking to 10.0.10.3' },
        ],
      },
      agent: owner,
    })
    expect(dc.isError).toBe(true)
    const dcText = dc.content.map(block => 'text' in block ? block.text : '').join('')
    expect(dcText).toContain(BOTH_LAN_CONVERSATION_REASON)
    expect(dcText).not.toContain('198.51.100.80')
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'other-end')).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'c2-domain')).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'extra-wan')).toBe(false)
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
    expect(foldExtras(owner.session.events)).toBeUndefined()
    const lanC2 = await ctx.tools.execute({
      signal,
      callId: CallId('bind-lan-c2'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'conv-1',
        endpoints: [
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' },
          { addr: '10.0.10.3', role: 'c2', because: 'LAN DC' },
        ],
      },
      agent: owner,
    })
    expect(lanC2.isError).toBe(true)
    expect(lanC2.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'unbound: role c2 cannot be a LAN address.',
    )
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'other-end')).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'c2-domain')).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'extra-wan')).toBe(false)
    const coerced = await ctx.tools.execute({
      signal,
      callId: CallId('bind-cue-ok'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: '443', t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: JSON.stringify([
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' },
        ]),
      },
      agent: owner,
    })
    expect(coerced.isError).toBe(false)
    expect(ctx.investigation.bind(owner.session)?.endpoints).toEqual([
      { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' },
      { addr: '198.51.100.80', role: 'c2', because: 'cue/observation address' },
    ])
  })

  it('auto-runs other-end after a cue-as-victim deny and harvests the LAN peer', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
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
      execute: (args) => {
        calls.push(args)
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter === 'ip.dst == 198.51.100.80') {
          return Promise.resolve({ text: 'ip.src: 10.0.10.2\tip.dst: 198.51.100.80' })
        }
        return Promise.resolve({ text: '' })
      },
    }))
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
    const denied = await ctx.tools.execute({
      signal,
      callId: CallId('bind-cue'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'conv-1',
        endpoints: [{ addr: '198.51.100.80', role: 'victim', because: 'the alert named this IP' }],
      },
      agent: owner,
    })
    expect(denied.isError).toBe(true)
    expect(denied.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'unbound: hunt LAN ip.src talking to 198.51.100.80 (ip.dst == 198.51.100.80).',
    )
    expect(calls).toEqual(expect.arrayContaining([
      {
        path: 'evidence/a.pcap',
        display_filter: 'ip.dst == 198.51.100.80',
        fields: ['ip.src'],
      },
    ]))
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
    expect(ctx.investigation.identities(owner.session).some(item => item.value === '10.0.10.2')).toBe(true)
    expect(owner.session.events.some(event => event.type === 'investigation/bind')).toBe(false)
    expect(owner.session.events.some(event => event.type === 'investigation/report')).toBe(false)
    const again = await ctx.tools.execute({
      signal,
      callId: CallId('bind-cue-again'),
      name: 'bind_relationship',
      arguments: {
        src: '198.51.100.80', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'conv-1',
        endpoints: [
          { addr: '198.51.100.80', role: 'victim', because: 'same cue' },
          { addr: '198.51.100.80', role: 'c2', because: 'same cue' },
        ],
      },
      agent: owner,
    })
    expect(again.isError).toBe(true)
    expect(again.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'unbound: hunt LAN ip.src talking to 198.51.100.80 (ip.dst == 198.51.100.80).',
    )
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
    const claims = { what: 'beacon', when: 'now', why: 'c2', how: 'https' }
    const unbound = await ctx.tools.execute({
      signal, callId: CallId('close-still-unbound'), name: 'case_report', arguments: claims, agent: owner,
    })
    expect(unbound.isError).toBe(true)
    expect(unbound.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'unbound: assign victim vs c2 on the cited conversation.',
    )
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-lan'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
    expect(ctx.investigation.bind(owner.session)?.endpoints.some(endpoint => (
      endpoint.role === 'victim' && endpoint.addr === '10.0.10.2'
    ))).toBe(true)
    const closed = await ctx.tools.execute({
      signal, callId: CallId('close-after-hunt'), name: 'case_report', arguments: claims, agent: owner,
    })
    expect(closed.isError).toBe(false)
    expect(owner.session.events.some(event => event.type === 'investigation/bind')).toBe(true)
    expect(ctx.investigation.bind(owner.session)?.endpoints.some(endpoint => endpoint.addr === '198.51.100.80' && endpoint.role === 'victim')).toBe(false)
  })

  it('records other-end on cue-as-victim when autoHunt is off and does not run pcap_filter', async () => {
    const { ctx, caseDir, owner } = await setup({ autoHunt: false })
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
        return Promise.resolve({ text: 'ip.src: 10.0.10.2' })
      },
    }))
    const denied = await ctx.tools.execute({
      signal,
      callId: CallId('bind-cue-no-auto'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'conv-1',
        endpoints: [{ addr: '198.51.100.80', role: 'victim', because: 'the alert named this IP' }],
      },
      agent: owner,
    })
    expect(denied.isError).toBe(true)
    expect(denied.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'unbound: hunt LAN ip.src talking to 198.51.100.80 (ip.dst == 198.51.100.80).',
    )
    expect(ctx.investigation.hunts(owner.session)).toEqual([
      { kind: 'other-end', subjectKind: 'ip', subject: '198.51.100.80' },
    ])
    expect(calls).toEqual([])
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
    expect(ctx.investigation.identities(owner.session)).toEqual([])
  })

  it('auto-issues and auto-runs c2-domain after a live bind and persists the C2 name', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    const DOMAIN = 'c2.example.test'
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'ip', value: '10.0.10.2', label: 'IP',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'lan-host', label: 'hostname', entity_id: '10.0.10.2', evidence_id: '10.0.10.2',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'dc01', label: 'hostname', evidence_id: '10.0.10.3',
    })
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
      execute: (args) => {
        calls.push(args)
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter.includes('tls.handshake.extensions_server_name') && filter.includes('198.51.100.80')) {
          return Promise.resolve({
            text: [
              `tls.handshake.extensions_server_name: ${DOMAIN}`,
              'dns.qry.name: c2.example.test',
              'hostname: desktop-lan',
              'NBNS Registration NB DC01<00>',
              'BROWSER Domain/Workgroup Announcement WORKGROUP',
            ].join('\n'),
          })
        }
        return Promise.resolve({ text: '' })
      },
    }))
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-c2-domain'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'extra-wan', subjectKind: 'ip', subject: '10.0.10.2',
    })
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'c2-domain', subjectKind: 'ip', subject: '198.51.100.80',
    })
    expect(calls).toEqual(expect.arrayContaining([
      {
        path: 'evidence/a.pcap',
        display_filter:
          '(tls.handshake.extensions_server_name or dns.qry.name or dns.resp.name) and ip.addr == 198.51.100.80',
        fields: [
          'tls.handshake.extensions_server_name',
          'dns.qry.name',
          'dns.resp.name',
        ],
      },
    ]))
    expect(ctx.investigation.identities(owner.session)).toContainEqual({
      kind: 'hostname', value: DOMAIN, label: 'hostname', evidence_id: '198.51.100.80',
    })
    expect(ctx.investigation.identities(owner.session).some(item => (
      item.kind === 'hostname' && item.value === 'desktop-lan' && item.evidence_id === '198.51.100.80'
    ))).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => (
      hunt.kind === 'kerberos-cname' && hunt.subject === DOMAIN
    ))).toBe(false)
    const report = requireCaseReport(
      ctx.investigation.bind(owner.session),
      ctx.investigation.identities(owner.session),
      { what: 'beacon', when: 'now', why: 'c2', how: 'https' },
    )
    ctx.investigation.recordReport(owner.session, report)
    expect(report.c2_domain).toBe(DOMAIN)
    expect(report.c2_ips).toEqual(['198.51.100.80'])
    expect(report.who.hostname).toBe('lan-host')
    expect(report.where.hostname).toBe('lan-host')
    expect(report.who.hostname).not.toBe(DOMAIN)
    expect(report.where.hostname).not.toBe(DOMAIN)
    expect(report.who.entity_id).toBe('10.0.10.2')
    expect(report.where.entity_id).toBe('10.0.10.2')
    expect(ctx.investigation.report(owner.session)?.c2_domain).toBe(DOMAIN)
  })

  it('auto-issues extra-wan after a live bind and persists extra C2 IPs and domain', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    const DOMAIN = 'c2.example.test'
    const EXTRA = '203.0.113.50'
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'ip', value: '10.0.10.2', label: 'IP',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'ip', value: '203.0.113.99', label: 'IP',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'lan-host', label: 'hostname', entity_id: '10.0.10.2', evidence_id: '10.0.10.2',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'dc01', label: 'hostname', evidence_id: '10.0.10.3',
    })
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
      execute: (args) => {
        calls.push(args)
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter.includes('ip.src == 10.0.10.2') && filter.includes('ip.dst')) {
          return Promise.resolve({
            text: [
              `ip.dst: ${EXTRA}`,
              'ip.dst: 10.0.10.3',
              'ip.dst: 10.0.10.1',
              'ip.dst: 224.0.0.252',
            ].join('\n'),
          })
        }
        if (filter.includes('tls.handshake.extensions_server_name') && filter.includes(EXTRA)) {
          return Promise.resolve({
            text: [
              `tls.handshake.extensions_server_name: ${DOMAIN}`,
              'hostname: desktop-lan',
            ].join('\n'),
          })
        }
        return Promise.resolve({ text: '' })
      },
    }))
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-extra-wan'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'extra-wan', subjectKind: 'ip', subject: '10.0.10.2',
    })
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'c2-domain', subjectKind: 'ip', subject: '198.51.100.80',
    })
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'c2-domain', subjectKind: 'ip', subject: EXTRA,
    })
    expect(calls).toEqual(expect.arrayContaining([
      expect.objectContaining({
        path: 'evidence/a.pcap',
        fields: ['ip.dst'],
      }),
      {
        path: 'evidence/a.pcap',
        display_filter:
          '(tls.handshake.extensions_server_name or dns.qry.name or dns.resp.name) and ip.addr == 198.51.100.80',
        fields: [
          'tls.handshake.extensions_server_name',
          'dns.qry.name',
          'dns.resp.name',
        ],
      },
      {
        path: 'evidence/a.pcap',
        display_filter:
          `(tls.handshake.extensions_server_name or dns.qry.name or dns.resp.name) and ip.addr == ${EXTRA}`,
        fields: [
          'tls.handshake.extensions_server_name',
          'dns.qry.name',
          'dns.resp.name',
        ],
      },
    ]))
    const extraWanCall = calls.find(call => Array.isArray(call.fields) && call.fields[0] === 'ip.dst')
    expect(typeof extraWanCall?.display_filter).toBe('string')
    expect(extraWanCall?.display_filter).toContain('ip.src == 10.0.10.2')
    expect(extraWanCall?.display_filter).toContain('not ip.dst == 198.51.100.80')
    expect(ctx.investigation.identities(owner.session)).toContainEqual({
      kind: 'ip', value: EXTRA, label: 'IP', evidence_id: '10.0.10.2',
    })
    expect(ctx.investigation.identities(owner.session)).toContainEqual({
      kind: 'ip', value: '203.0.113.99', label: 'IP',
    })
    expect(ctx.investigation.hunts(owner.session).some(hunt => (
      hunt.kind === 'c2-domain' && hunt.subject === '203.0.113.99'
    ))).toBe(false)
    expect(ctx.investigation.identities(owner.session)).toContainEqual({
      kind: 'hostname', value: DOMAIN, label: 'hostname', evidence_id: EXTRA,
    })
    expect(ctx.investigation.identities(owner.session).some(item => (
      item.kind === 'hostname' && item.value === 'desktop-lan' && item.evidence_id === EXTRA
    ))).toBe(false)
    const report = requireCaseReport(
      ctx.investigation.bind(owner.session),
      ctx.investigation.identities(owner.session),
      { what: 'beacon', when: 'now', why: 'c2', how: 'https' },
    )
    ctx.investigation.recordReport(owner.session, report)
    expect(report.c2_ips).toEqual(['198.51.100.80', EXTRA])
    expect(report.c2_ips).toContain('198.51.100.80')
    expect(report.c2_ips).not.toContain('203.0.113.99')
    expect(report.c2_ips).not.toContain('10.0.10.3')
    expect(report.c2_ips).not.toContain('10.0.10.1')
    expect(report.c2_domain).toBe(DOMAIN)
    expect(report.who.hostname).toBe('lan-host')
    expect(report.where.hostname).toBe('lan-host')
    expect(report.who.hostname).not.toBe(DOMAIN)
    expect(report.where.hostname).not.toBe(DOMAIN)
    expect(ctx.investigation.bind(owner.session)?.endpoints.filter(endpoint => endpoint.role === 'c2'))
      .toHaveLength(1)
  })

  it('issues neither extra-wan nor c2-domain when the live bind has two C2s', async () => {
    const { ctx, owner } = await setup()
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-two-c2'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' },
          { addr: '198.51.100.80', role: 'c2', because: 'cue' },
          { addr: '203.0.113.50', role: 'c2', because: 'second WAN peer' },
        ],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'extra-wan')).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'c2-domain')).toBe(false)
    expect(requireCaseReport(
      ctx.investigation.bind(owner.session),
      ctx.investigation.identities(owner.session),
      { what: 'a', when: 'b', why: 'c', how: 'd' },
    ).c2_ips).toBeUndefined()
  })

  it('does not issue c2-domain from extra-wan when no bind is live', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    ctx.investigation.recordHunt(owner.session, {
      kind: 'extra-wan', subjectKind: 'ip', subject: '10.0.10.2',
    })
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
      execute: () => Promise.resolve({ text: 'ip.dst: 203.0.113.50' }),
    }))
    const echoed = await ctx.tools.execute({
      signal, callId: CallId('echo-extra-wan-unbound'), name: 'echo',
      arguments: { text: '10.0.10.2' }, agent: owner,
    })
    expect(echoed.isError).toBe(false)
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'c2-domain')).toBe(false)
    expect(ctx.investigation.identities(owner.session)).toContainEqual({
      kind: 'ip', value: '203.0.113.50', label: 'IP', evidence_id: '10.0.10.2',
    })
  })

  it('denies a CDN/update C2 bind and issues neither extra-wan nor c2-domain', async () => {
    const { ctx, owner } = await setup()
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'update.microsoft.com', label: 'hostname', evidence_id: '203.0.113.80',
    })
    const denied = await ctx.tools.execute({
      signal,
      callId: CallId('bind-cdn-c2'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '203.0.113.80', dport: 443, t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-cdn',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 203.0.113.80' }],
      },
      agent: owner,
    })
    expect(denied.isError).toBe(true)
    expect(denied.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      CDN_C2_REASON,
    )
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
    expect(owner.session.events.some(event => event.type === 'investigation/bind')).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'extra-wan')).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'c2-domain')).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'other-end')).toBe(false)
    expect(foldExtras(owner.session.events)).toBeUndefined()
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'payload.example.test', label: 'hostname', evidence_id: '198.51.100.80',
    })
    const accepted = await ctx.tools.execute({
      signal,
      callId: CallId('bind-payload-c2'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(accepted.isError).toBe(false)
    expect(ctx.investigation.bind(owner.session)?.endpoints).toEqual([
      { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' },
      { addr: '198.51.100.80', role: 'c2', because: 'cue/observation address' },
    ])
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'extra-wan', subjectKind: 'ip', subject: '10.0.10.2',
    })
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'c2-domain', subjectKind: 'ip', subject: '198.51.100.80',
    })
  })

  it('drops a CDN extra from c2_ips and persists payload.example.test from another C2 IP', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    const PAYLOAD = 'payload.example.test'
    const CDN_DEST = '203.0.113.80'
    const EXTRA = '203.0.113.50'
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'ip', value: '10.0.10.2', label: 'IP',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'lan-host', label: 'hostname', entity_id: '10.0.10.2', evidence_id: '10.0.10.2',
    })
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
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter.includes('ip.src == 10.0.10.2') && filter.includes('ip.dst')) {
          return Promise.resolve({ text: `ip.dst: ${CDN_DEST}\nip.dst: ${EXTRA}` })
        }
        if (filter.includes('tls.handshake.extensions_server_name') && filter.includes(CDN_DEST)) {
          return Promise.resolve({ text: 'tls.handshake.extensions_server_name: update.microsoft.com' })
        }
        if (filter.includes('tls.handshake.extensions_server_name') && filter.includes(EXTRA)) {
          return Promise.resolve({ text: `tls.handshake.extensions_server_name: ${PAYLOAD}` })
        }
        if (filter.includes('tls.handshake.extensions_server_name') && filter.includes('198.51.100.80')) {
          return Promise.resolve({ text: `tls.handshake.extensions_server_name: ${PAYLOAD}` })
        }
        return Promise.resolve({ text: '' })
      },
    }))
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-cdn-extra'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
    const report = requireCaseReport(
      ctx.investigation.bind(owner.session),
      ctx.investigation.identities(owner.session),
      { what: 'beacon', when: 'now', why: 'c2', how: 'https' },
    )
    expect(report.c2_ips).toEqual(['198.51.100.80', EXTRA])
    expect(report.c2_ips).not.toContain(CDN_DEST)
    expect(report.c2_domain).toBe(PAYLOAD)
    expect(report.who.hostname).toBe('lan-host')
    expect(report.where.hostname).toBe('lan-host')
  })

  it('persists leftover extras from the Report hook without an accepted close', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    const PAYLOAD = 'payload.example.test'
    const CDN_DEST = '203.0.113.80'
    const EXTRA = '203.0.113.50'
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'lan-host', label: 'hostname', entity_id: '10.0.10.2', evidence_id: '10.0.10.2',
    })
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
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter.includes('ip.src == 10.0.10.2') && filter.includes('ip.dst')) {
          return Promise.resolve({ text: `ip.dst: ${CDN_DEST}\nip.dst: ${EXTRA}` })
        }
        if (filter.includes('tls.handshake.extensions_server_name') && filter.includes(CDN_DEST)) {
          return Promise.resolve({ text: 'tls.handshake.extensions_server_name: update.microsoft.com' })
        }
        if (filter.includes('tls.handshake.extensions_server_name') && filter.includes(EXTRA)) {
          return Promise.resolve({
            text: `tls.handshake.extensions_server_name: intranet\ntls.handshake.extensions_server_name: ${PAYLOAD}`,
          })
        }
        return Promise.resolve({ text: '' })
      },
    }))
    ctx.tools.register(defineTool({
      name: 'case_report',
      description: 'Close stand-in.',
      parameters: {
        what: { type: 'string', required: true },
        when: { type: 'string', required: true },
        why: { type: 'string', required: true },
        how: { type: 'string', required: true },
        who: { type: 'string' },
      },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true } } },
        render: () => [{ type: 'text', text: 'closed' }],
      },
      execute: () => Promise.resolve({ ok: true }),
    }))
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-leftover-extras'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
    const extras = foldExtras(owner.session.events)
    expect(extras?.c2_ips).toEqual(['198.51.100.80', EXTRA])
    expect(extras?.c2_ips).not.toContain(CDN_DEST)
    expect(extras?.c2_domain).toBe(PAYLOAD)
    expect(ctx.investigation.extras(owner.session)).toEqual(extras)
    expect(foldReport(owner.session.events)).toBeUndefined()
    expect(owner.session.events.some(event => event.type === 'investigation/report')).toBe(false)
    expect(ctx.investigation.report(owner.session)).toBeUndefined()
    expect(foldActions(owner.session.events).every(action => action.hypothesis_id === 'h-c2')).toBe(true)
    expect(foldActions(owner.session.events).some(action => action.thesis.result === 'confirm')).toBe(true)
    const unbound = await ctx.tools.execute({
      signal,
      callId: CallId('close-unbound-who'),
      name: 'case_report',
      arguments: {
        what: 'beacon', when: 'now', why: 'c2', how: 'https',
        who: 'the cue at 198.51.100.80',
      },
      agent: owner,
    })
    expect(unbound.isError).toBe(true)
    expect(foldExtras(owner.session.events)?.c2_ips).toEqual(['198.51.100.80', EXTRA])
    expect(foldExtras(owner.session.events)?.c2_domain).toBe(PAYLOAD)
    expect(foldReport(owner.session.events)).toBeUndefined()
    const report = requireCaseReport(
      ctx.investigation.bind(owner.session),
      ctx.investigation.identities(owner.session),
      { what: 'beacon', when: 'now', why: 'c2', how: 'https' },
    )
    ctx.investigation.recordReport(owner.session, report)
    expect(foldReport(owner.session.events)?.c2_ips).toEqual(['198.51.100.80', EXTRA])
    expect(foldReport(owner.session.events)?.c2_domain).toBe(PAYLOAD)
    expect(foldReport(owner.session.events)?.what).toBe('beacon')
    expect(foldReport(owner.session.events)?.who.entity_id).toBe('10.0.10.2')
    expect(foldReport(owner.session.events)?.who.hostname).toBe('lan-host')
    expect(foldReport(owner.session.events)?.where.hostname).toBe('lan-host')
  })

  it('does not auto-hunt leftover extras after Mission alone', async () => {
    const { ctx, caseDir, owner } = await setup({}, { mindset: false })
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
    const calls: unknown[] = []
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
        return Promise.resolve({ text: 'ip.dst: 203.0.113.50' })
      },
    }))
    ctx.investigation.recordMission(owner.session, {
      purpose: CHASSIS_MISSION_PURPOSE,
      slots: { '0a': { value: 'valid' } },
      closedMeans: [...CHASSIS_CLOSED_MEANS],
      cue: { addr: '198.51.100.80', evidence_id: 'conv-1' },
      cueValidation: 'valid',
    })
    const denied = await ctx.tools.execute({
      signal,
      callId: CallId('bind-mission-only'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(denied.isError).toBe(true)
    expect(denied.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      PLAN_C2_HYPOTHESIS_REASON,
    )
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'extra-wan')).toBe(false)
    expect(ctx.investigation.hunts(owner.session).some(hunt => hunt.kind === 'c2-domain')).toBe(false)
    expect(foldExtras(owner.session.events)).toBeUndefined()
    ctx.investigation.recordHunt(owner.session, {
      kind: 'extra-wan', subjectKind: 'ip', subject: '10.0.10.2',
    })
    const echoed = await ctx.tools.execute({
      signal, callId: CallId('echo-mission-only'), name: 'echo',
      arguments: { text: '10.0.10.2' }, agent: owner,
    })
    expect(echoed.isError).toBe(false)
    const filters = calls.map(item => (
      typeof item === 'object' && item !== null && 'display_filter' in item
        ? String((item as { display_filter?: unknown }).display_filter)
        : ''
    ))
    expect(filters.some(filter => filter.includes('tls.handshake.extensions_server_name'))).toBe(false)
    expect(filters.some(filter => filter.includes('not ip.dst'))).toBe(false)
    expect(foldExtras(owner.session.events)).toBeUndefined()
  })

  it('appends Mission and Plan and denies an empty or malformed Plan', async () => {
    const { ctx, owner } = await setup({}, { mindset: false })
    const blank = await ctx.tools.execute({
      signal,
      callId: CallId('mission-blank'),
      name: 'investigation_mission',
      arguments: {
        purpose: '   ',
        cue_addr: '198.51.100.80',
        cue_evidence_id: 'conv-1',
        cue_validation: 'valid',
      },
      agent: owner,
    })
    expect(blank.isError).toBe(true)
    expect(blank.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      MISSION_PURPOSE_REASON,
    )
    const overwrite = await ctx.tools.execute({
      signal,
      callId: CallId('mission-overwrite'),
      name: 'investigation_mission',
      arguments: {
        purpose: 'Hunt malware family and origin',
        cue_addr: '198.51.100.80',
        cue_evidence_id: 'conv-1',
        cue_validation: 'valid',
      },
      agent: owner,
    })
    expect(overwrite.isError).toBe(true)
    expect(overwrite.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      MISSION_PURPOSE_REASON,
    )
    const blankCue = await ctx.tools.execute({
      signal,
      callId: CallId('mission-blank-cue'),
      name: 'investigation_mission',
      arguments: {
        purpose: CHASSIS_MISSION_PURPOSE,
        cue_addr: '   ',
        cue_evidence_id: 'conv-1',
        cue_validation: 'valid',
      },
      agent: owner,
    })
    expect(blankCue.isError).toBe(true)
    const mission = await ctx.tools.execute({
      signal,
      callId: CallId('mission-ok'),
      name: 'investigation_mission',
      arguments: {
        purpose: CHASSIS_MISSION_PURPOSE,
        cue_addr: '198.51.100.80',
        cue_evidence_id: 'conv-1',
        cue_validation: 'open',
        closed_means: ['origin', ''],
      },
      agent: owner,
    })
    expect(mission.isError).toBe(false)
    expect(foldMission(owner.session.events)?.cueValidation).toBe('open')
    expect(foldMission(owner.session.events)?.purpose).toBe(CHASSIS_MISSION_PURPOSE)
    expect(ctx.investigation.mission(owner.session)?.closedMeans).toEqual([...CHASSIS_CLOSED_MEANS])
    const restamp = await ctx.tools.execute({
      signal,
      callId: CallId('mission-no-means'),
      name: 'investigation_mission',
      arguments: {
        purpose: CHASSIS_MISSION_PURPOSE,
        cue_addr: '198.51.100.80',
        cue_evidence_id: 'conv-1',
        cue_validation: 'open',
      },
      agent: owner,
    })
    expect(restamp.isError).toBe(false)
    expect(ctx.investigation.mission(owner.session)?.closedMeans).toEqual([...CHASSIS_CLOSED_MEANS])
    const noAgent = await ctx.tools.execute({
      signal,
      callId: CallId('mission-no-agent'),
      name: 'investigation_mission',
      arguments: {
        purpose: CHASSIS_MISSION_PURPOSE,
        cue_addr: '198.51.100.80',
        cue_evidence_id: 'conv-1',
        cue_validation: 'valid',
      },
    })
    expect(noAgent.isError).toBe(true)
    const planNoAgent = await ctx.tools.execute({
      signal,
      callId: CallId('plan-no-agent'),
      name: 'investigation_plan',
      arguments: { inventory: ['evidence/a.pcap'] },
    })
    expect(planNoAgent.isError).toBe(true)
    const emptyPlan = await ctx.tools.execute({
      signal,
      callId: CallId('plan-empty'),
      name: 'investigation_plan',
      arguments: {},
      agent: owner,
    })
    expect(emptyPlan.isError).toBe(true)
    const badClaim = await ctx.tools.execute({
      signal,
      callId: CallId('plan-claim'),
      name: 'investigation_plan',
      arguments: {
        hypotheses: [{
          id: 'h-bad',
          claim: '198.51.100.80 is C2',
          disconfirm: 'SNI is CDN',
          label: 'c2',
        }],
      },
      agent: owner,
    })
    expect(badClaim.isError).toBe(true)
    expect(badClaim.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      'I believe X because Y',
    )
    const plan = await ctx.tools.execute({
      signal,
      callId: CallId('plan-ok'),
      name: 'investigation_plan',
      arguments: {
        inventory: ['evidence/a.pcap'],
        gaps: ['C2 domain unknown'],
        hypotheses: [{
          id: 'h-c2',
          claim: 'I believe 198.51.100.80 is C2 because 10.0.10.2 talks to that non-LAN cue',
          disconfirm: 'SNI is a CDN or update name',
          label: 'c2',
        }, {
          id: 'h-cdn',
          claim: 'I believe 203.0.113.80 is CDN because update.microsoft.com is evidenced there',
          disconfirm: 'a non-CDN dotted name is evidenced on that IP',
          label: 'cdn',
        }],
      },
      agent: owner,
    })
    expect(plan.isError).toBe(false)
    const more = await ctx.tools.execute({
      signal,
      callId: CallId('plan-append'),
      name: 'investigation_plan',
      arguments: {
        hypotheses: [{
          id: 'h-c2',
          claim: 'I believe 198.51.100.80 is C2 because a later question replaced this',
          disconfirm: 'replaced',
          label: 'c2',
        }, {
          id: 'h-dc',
          claim: 'I believe 10.0.10.3 is a DC because it answers Kerberos',
          disconfirm: 'it talks only to the cue',
          label: 'dc',
        }],
      },
      agent: owner,
    })
    expect(more.isError).toBe(false)
    expect(foldPlan(owner.session.events).hypotheses.map(item => item.id)).toEqual(['h-c2', 'h-cdn', 'h-dc'])
    expect(foldPlan(owner.session.events).hypotheses[0]?.disconfirm).toBe('SNI is a CDN or update name')
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-after-open-cue'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
  })

  it('folds leftover extras onto an already-accepted 5W1H packet', async () => {
    const { ctx, owner } = await setup({ autoHunt: false })
    const EXTRA = '203.0.113.50'
    const PAYLOAD = 'payload.example.test'
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'lan-host', label: 'hostname', entity_id: '10.0.10.2', evidence_id: '10.0.10.2',
    })
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-overlay-extras'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
    expect(foldExtras(owner.session.events)?.c2_ips).toEqual(['198.51.100.80'])
    const report = requireCaseReport(
      ctx.investigation.bind(owner.session),
      ctx.investigation.identities(owner.session),
      { what: 'beacon', when: 'now', why: 'c2', how: 'https' },
    )
    ctx.investigation.recordReport(owner.session, report)
    expect(foldReport(owner.session.events)?.c2_ips).toEqual(['198.51.100.80'])
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'ip', value: EXTRA, label: 'IP', evidence_id: '10.0.10.2',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: PAYLOAD, label: 'hostname', evidence_id: EXTRA,
    })
    const echoed = await ctx.tools.execute({
      signal, callId: CallId('echo-overlay-extras'), name: 'echo',
      arguments: { text: EXTRA }, agent: owner,
    })
    expect(echoed.isError).toBe(false)
    expect(foldExtras(owner.session.events)?.c2_ips).toEqual(['198.51.100.80', EXTRA])
    expect(foldExtras(owner.session.events)?.c2_domain).toBe(PAYLOAD)
    expect(foldReport(owner.session.events)?.c2_ips).toEqual(['198.51.100.80', EXTRA])
    expect(foldReport(owner.session.events)?.c2_domain).toBe(PAYLOAD)
    expect(foldReport(owner.session.events)?.what).toBe('beacon')
    expect(foldReport(owner.session.events)?.who.entity_id).toBe('10.0.10.2')
  })

  it('records a kill Action when c2-domain harvests only a CDN name', async () => {
    const { ctx, caseDir, owner } = await setup()
    await mkdir(join(caseDir, 'evidence'), { recursive: true })
    await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
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
        const filter = typeof args.display_filter === 'string' ? args.display_filter : ''
        if (filter.includes('tls.handshake.extensions_server_name')) {
          return Promise.resolve({
            text: 'tls.handshake.extensions_server_name: intranet\ntls.handshake.extensions_server_name: update.microsoft.com',
          })
        }
        return Promise.resolve({ text: 'ip.dst:' })
      },
    }))
    const bound = await ctx.tools.execute({
      signal,
      callId: CallId('bind-kill-cdn-sni'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(bound.isError).toBe(false)
    expect(foldActions(owner.session.events).some(action => action.thesis.result === 'kill')).toBe(true)
    expect(foldActions(owner.session.events).some(action => action.thesis.result === 'gap')).toBe(true)
    expect(foldExtras(owner.session.events)?.killed).toContain('h-c2')
  })

  it('chassis-stamps Mission so identity hunts run and bind still needs a C2 hypothesis', async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-investigation-chassis-'))
    const ctx = new Context()
    await ctx.plugin(SessionStore)
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(Investigation, { caseDir: root, evidenceReadOnly: true, autoHunt: true })
    const session = ctx.sessions.create()
    expect(foldMission(session.events)?.purpose).toBe(CHASSIS_MISSION_PURPOSE)
    expect(foldMission(session.events)?.closedMeans).toEqual([...CHASSIS_CLOSED_MEANS])
    expect(ctx.investigation.ensureChassisMission(session)).toBe(false)
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
    const owner = { id: session.id, session } as unknown as Agent
    const echoed = await ctx.tools.execute({
      signal, callId: CallId('echo-chassis-ip'), name: 'echo',
      arguments: { text: '10.0.10.2' }, agent: owner,
    })
    expect(echoed.isError).toBe(false)
    expect(ctx.investigation.hunts(session).some(hunt => hunt.kind === 'eth-src')).toBe(true)
    expect(ctx.investigation.hunts(session).some(hunt => hunt.kind === 'extra-wan')).toBe(false)
    const denied = await ctx.tools.execute({
      signal,
      callId: CallId('bind-chassis-only'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
        endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
      },
      agent: owner,
    })
    expect(denied.isError).toBe(true)
    expect(denied.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      PLAN_C2_HYPOTHESIS_REASON,
    )
  })

  it('denies a resolved bind with the matching Plan reason', async () => {
    const { ctx, owner } = await setup({}, { mindset: false })
    const bindArgs = {
      src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
      endpoints: [{ addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80' }],
    }
    const execute = (callId: string) => ctx.tools.execute({
      signal, callId: CallId(callId), name: 'bind_relationship', arguments: bindArgs, agent: owner,
    })
    ctx.investigation.recordMission(owner.session, {
      ...ctx.investigation.mission(owner.session) ?? {
        purpose: CHASSIS_MISSION_PURPOSE,
        slots: { '0a': { value: 'valid' } },
        closedMeans: [...CHASSIS_CLOSED_MEANS],
        cue: { addr: '198.51.100.80', evidence_id: 'conv-1' },
        cueValidation: 'valid',
      },
    })
    ctx.investigation.recordPlan(owner.session, {
      inventory: ['evidence/a.pcap'],
      hypotheses: [{
        id: 'h-c2',
        claim: 'I believe 198.51.100.80 is C2 because 10.0.10.2 talks to that non-LAN cue',
        disconfirm: 'SNI is a CDN or update name',
        label: 'c2',
      }],
    })
    const noAlt = await execute('bind-no-alt')
    expect(noAlt.isError).toBe(true)
    expect(noAlt.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      PLAN_ALTERNATIVE_REASON,
    )
    ctx.investigation.recordPlan(owner.session, {
      hypotheses: [{
        id: 'h-cdn',
        claim: 'I believe 203.0.113.80 is CDN because update.microsoft.com is evidenced there',
        disconfirm: 'a non-CDN dotted name is evidenced on that IP',
        label: 'cdn',
      }],
    })
    const ready = await execute('bind-ready-after-alt')
    expect(ready.isError).toBe(false)

    const { ctx: ctx2, owner: owner2 } = await setup({}, { mindset: false })
    ctx2.investigation.recordPlan(owner2.session, {
      hypotheses: [{
        id: 'h-c2',
        claim: 'I believe 198.51.100.80 is C2 because 10.0.10.2 talks to that non-LAN cue',
        disconfirm: 'SNI is a CDN or update name',
        label: 'c2',
      }, {
        id: 'h-cdn',
        claim: 'I believe 203.0.113.80 is CDN because update.microsoft.com is evidenced there',
        disconfirm: 'a non-CDN dotted name is evidenced on that IP',
        label: 'cdn',
      }],
    })
    const noInventory = await ctx2.tools.execute({
      signal, callId: CallId('bind-no-inventory'), name: 'bind_relationship',
      arguments: bindArgs, agent: owner2,
    })
    expect(noInventory.isError).toBe(true)
    expect(noInventory.content.map(block => 'text' in block ? block.text : '').join('')).toContain(
      PLAN_INVENTORY_REASON,
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
    expect(ctx.tools.get('investigation_mission')).toBeDefined()
    expect(ctx.tools.get('investigation_plan')).toBeDefined()
    await fiber.dispose()
    expect(ctx.get('investigation')).toBeUndefined()
    expect(ctx.tools.get('bind_relationship')).toBeUndefined()
    expect(ctx.tools.get('investigation_mission')).toBeUndefined()
    expect(ctx.tools.get('investigation_plan')).toBeUndefined()
  })
})
