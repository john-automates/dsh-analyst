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
      who: 'a', what: 'b', when: 'c', where: 'd', why: 'e', how: 'f', ...over,
    },
  } as SessionEvent
}

describe('investigation invariants', () => {
  it('accepts well-formed ledger events and ignores unrelated types', async () => {
    const ctx = await setup()
    const session = ctx.sessions.create()
    session.append('investigation/identity', { kind: 'user', value: 'brolf', label: 'user' })
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
    [report({ who: '' }), /who must be a non-empty/],
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
