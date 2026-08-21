import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import SessionStore, { type Session, type SessionEvent } from '@deepseek-ai/dsh-session'
import InvariantRegistry from '@deepseek-ai/dsh-invariants'
import * as InvestigationInvariant from '../src/invariant.ts'

async function setup(): Promise<Context> {
  const ctx = new Context()
  await ctx.plugin(SessionStore)
  await ctx.plugin(InvariantRegistry, { enabled: true })
  await ctx.plugin(InvestigationInvariant)
  return ctx
}

function identity(over: Record<string, unknown> = {}): SessionEvent {
  return {
    type: 'investigation/identity',
    seq: 0,
    time: 0,
    data: { kind: 'ip', value: '10.0.0.5', label: 'IP', ...over },
  } as SessionEvent
}

function hunt(over: Record<string, unknown> = {}): SessionEvent {
  return {
    type: 'investigation/hunt',
    seq: 0,
    time: 0,
    data: { kind: 'kerberos-cname', subjectKind: 'ip', subject: '10.0.0.5', ...over },
  } as SessionEvent
}

function report(over: Record<string, unknown> = {}): SessionEvent {
  return {
    type: 'investigation/report',
    seq: 0,
    time: 0,
    data: {
      who: { entity_id: '10.0.10.2', ip: '10.0.10.2' },
      what: 'b', when: 'c',
      where: { entity_id: '10.0.10.2', ip: '10.0.10.2' },
      why: 'e', how: 'f', ...over,
    },
  } as SessionEvent
}

function bind(over: Record<string, unknown> = {}): SessionEvent {
  return {
    type: 'investigation/bind',
    seq: 0,
    time: 0,
    data: {
      relationship: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
      },
      endpoints: [
        { addr: '10.0.10.2', role: 'victim', because: 'conversation' },
        { addr: '198.51.100.80', role: 'c2', because: 'cue' },
      ],
      ...over,
    },
  } as SessionEvent
}

describe('investigation invariants', () => {
  it('accepts well-formed ledger events and ignores unrelated types', async () => {
    const ctx = await setup()
    const session = ctx.sessions.create()
    session.append('investigation/identity', { kind: 'user', value: 'brolf', label: 'user' })
    session.append('investigation/identity', {
      kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', entity_id: '10.0.10.2', evidence_id: 'conv-1',
    })
    session.append('investigation/hunt', {
      kind: 'other-end', subjectKind: 'ip', subject: '198.51.100.80',
    })
    session.append('investigation/hunt', {
      kind: 'c2-domain', subjectKind: 'ip', subject: '198.51.100.80',
    })
    session.append('investigation/hunt', {
      kind: 'extra-wan', subjectKind: 'ip', subject: '10.0.10.2',
    })
    session.append('investigation/bind', {
      relationship: {
        src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
      },
      endpoints: [
        { addr: '10.0.10.2', role: 'victim', because: 'conversation' },
        { addr: '198.51.100.80', role: 'c2', because: 'cue' },
      ],
    })
    session.append('investigation/report', {
      who: { entity_id: '10.0.10.2', ip: '10.0.10.2', mac: '02:00:00:00:00:0a' },
      what: 'b', when: 'c',
      where: { entity_id: '10.0.10.2', ip: '10.0.10.2' },
      why: 'e', how: 'f',
      c2_domain: 'c2.example.test',
      c2_ips: ['198.51.100.80', '203.0.113.50'],
    })
    expect(() => { ctx.emit('session/event', {} as Session, { type: 'todo/write', seq: 0, time: 0, data: {} } as SessionEvent) }).not.toThrow()
    expect(session.events.some(event => event.type === 'investigation/identity')).toBe(true)
  })

  it.each([
    [identity({ kind: 'email' }), /unknown kind/],
    [identity({ value: '' }), /value must be a non-empty/],
    [identity({ label: ' padded ' }), /label must be a non-empty/],
    [hunt({ kind: 'dns' }), /unknown kind/],
    [hunt({ subjectKind: 'mac' }), /unknown subjectKind/],
    [hunt({ subject: '' }), /subject must be a non-empty/],
    [report({ who: '' }), /who must be a projected identity slot/],
    [report({ what: '' }), /what must be a non-empty/],
    [bind({ endpoints: [] }), /endpoints must be a non-empty/],
    [bind({ relationship: undefined }), /relationship is required/],
    [bind({ relationship: { src: '', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'e' } }), /src must be a non-empty/],
    [bind({ relationship: { src: '10.0.10.2', dst: '198.51.100.80', dport: 1.5, t: 't', evidence_id: 'e' } }), /dport must be an integer/],
    [bind({ endpoints: ['x'] }), /endpoint must be an object/],
    [bind({
      endpoints: [{ addr: '10.0.10.2', role: 'evil', because: 'conversation' }],
    }), /endpoint.role "evil" is not valid/],
    [report({ who: 1 }), /who must be a projected identity slot/],
    [identity({ entity_id: '' }), /entity_id must be a non-empty/],
    [identity({ evidence_id: '' }), /evidence_id must be a non-empty/],
    [report({ who: { entity_id: '10.0.10.2', mac: ' padded ' } }), /mac must be a non-empty/],
    [report({ who: { entity_id: '' } }), /entity_id must be a non-empty/],
    [report({ c2_domain: '' }), /c2_domain must be a non-empty/],
    [report({ c2_ips: [] }), /c2_ips must be a non-empty/],
    [report({ c2_ips: [''] }), /c2_ips\[0\] must be a non-empty/],
  ])('rejects an incoherent investigation event', async (event, message) => {
    const ctx = await setup()
    expect(() => { ctx.emit('session/event', {} as Session, event) }).toThrow(message)
  })

  it('seeds already-loaded sessions', async () => {
    const ctx = new Context()
    await ctx.plugin(SessionStore)
    ctx.sessions.create().append('investigation/identity', { kind: 'ip', value: '10.0.0.5', label: 'IP' })
    await ctx.plugin(InvariantRegistry, { enabled: true })
    await expect(ctx.plugin(InvestigationInvariant).then(() => undefined)).resolves.toBeUndefined()
  })
})
