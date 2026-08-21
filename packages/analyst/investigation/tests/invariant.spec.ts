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

function mission(over: Record<string, unknown> = {}): SessionEvent {
  return {
    type: 'investigation/mission',
    seq: 0,
    time: 0,
    data: {
      purpose: 'Scope an identity+C2 case',
      slots: { '0a': { value: 'valid' } },
      closedMeans: ['identity+c2'],
      cue: { addr: '198.51.100.80', evidence_id: 'conv-1' },
      cueValidation: 'valid',
      ...over,
    },
  } as SessionEvent
}

function plan(over: Record<string, unknown> = {}): SessionEvent {
  return {
    type: 'investigation/plan',
    seq: 0,
    time: 0,
    data: {
      inventory: ['evidence/a.pcap'],
      gaps: ['C2 domain unknown'],
      hypotheses: [{
        id: 'h-c2',
        claim: 'I believe 198.51.100.80 is C2 because 10.0.10.2 talks to that cue',
        disconfirm: 'SNI is a CDN or update name',
        label: 'c2',
      }],
      ...over,
    },
  } as SessionEvent
}

function action(over: Record<string, unknown> = {}): SessionEvent {
  return {
    type: 'investigation/action',
    seq: 0,
    time: 0,
    data: {
      huntKind: 'extra-wan',
      subject: '10.0.10.2',
      hypothesis_id: 'h-c2',
      thesis: {
        name: 'extra-wan',
        claim: 'I believe extra-wan produced a leftover C2 because the dump harvested a non-CDN dest',
        rule: 'non-CDN leftover on a remaining C2 IP',
        result: 'confirm',
      },
      ...over,
    },
  } as SessionEvent
}

function extras(over: Record<string, unknown> = {}): SessionEvent {
  return {
    type: 'investigation/extras',
    seq: 0,
    time: 0,
    data: { c2_ips: ['198.51.100.80'], c2_domain: 'payload.example.test', ...over },
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
    session.append('investigation/report', {
      who: { entity_id: '10.0.10.2', ip: '10.0.10.2' },
      what: 'b', when: 'c',
      where: { entity_id: '10.0.10.2', ip: '10.0.10.2' },
      why: 'e', how: 'f',
    })
    session.append('investigation/report', {
      who: { entity_id: '10.0.10.8', ip: '10.0.10.8' },
      what: 'b', when: 'c',
      where: { entity_id: '10.0.10.8', ip: '10.0.10.8' },
      why: 'e', how: 'f',
      victims: [
        { entity_id: '10.0.10.2', ip: '10.0.10.2' },
        { entity_id: '10.0.10.8', ip: '10.0.10.8' },
      ],
    })
    session.append('investigation/mission', {
      purpose: 'Scope an identity+C2 case',
      slots: { '0a': { value: 'valid' } },
      closedMeans: ['identity+c2'],
      cue: { addr: '198.51.100.80', evidence_id: 'conv-1' },
      cueValidation: 'valid',
    })
    session.append('investigation/plan', {
      hypotheses: [{
        id: 'h-c2',
        claim: 'I believe 198.51.100.80 is C2 because 10.0.10.2 talks to that cue',
        disconfirm: 'SNI is a CDN or update name',
        label: 'c2',
      }],
    })
    session.append('investigation/action', {
      huntKind: 'extra-wan',
      subject: '10.0.10.2',
      hypothesis_id: 'h-c2',
      evidence_id: '10.0.10.2',
      thesis: {
        name: 'extra-wan',
        claim: 'I believe extra-wan produced a leftover C2 because the dump harvested a non-CDN dest',
        rule: 'non-CDN leftover on a remaining C2 IP',
        result: 'confirm',
      },
    })
    session.append('investigation/extras', {
      c2_ips: ['198.51.100.80', '203.0.113.50'],
      c2_domain: 'payload.example.test',
      killed: ['h-cdn'],
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
    [report({ victims: [] }), /victims must be an array of two or more/],
    [report({ victims: [{ entity_id: '10.0.10.2', ip: '10.0.10.2' }] }), /victims must be an array of two or more/],
    [report({ victims: [{ entity_id: '10.0.10.2' }, { entity_id: '' }] }), /entity_id must be a non-empty/],
    [mission({ cueValidation: 'maybe' }), /cueValidation "maybe" is not valid/],
    [mission({ purpose: '' }), /purpose must be a non-empty/],
    [mission({ cue: null }), /cue must be an object/],
    [mission({ cue: { addr: '', evidence_id: 'conv-1' } }), /cue.addr must be a non-empty/],
    [mission({ cue: { addr: '198.51.100.80', evidence_id: '' } }), /cue.evidence_id must be a non-empty/],
    [mission({ closedMeans: 'identity+c2' }), /closedMeans must be an array/],
    [mission({ closedMeans: [''] }), /closedMeans\[0\] must be a non-empty/],
    [mission({ slots: [] }), /slots must be an object/],
    [plan({ inventory: 'evidence/a.pcap' }), /inventory must be an array/],
    [plan({ hypotheses: 'h-c2' }), /hypotheses must be an array/],
    [plan({ hypotheses: ['x'] }), /hypotheses\[0\] must be an object/],
    [plan({ hypotheses: [{ id: '', claim: 'c', disconfirm: 'd', label: 'c2' }] }), /id must be a non-empty/],
    [plan({ hypotheses: [{ id: 'h', claim: 'c', disconfirm: 'd', label: 'evil' }] }), /label "evil" is not valid/],
    [action({ huntKind: 'dns' }), /unknown huntKind/],
    [action({ subject: '' }), /subject must be a non-empty/],
    [action({ hypothesis_id: '' }), /hypothesis_id must be a non-empty/],
    [action({ evidence_id: '' }), /evidence_id must be a non-empty/],
    [action({ thesis: undefined }), /thesis is required/],
    [action({ thesis: { name: '', claim: 'c', rule: 'r', result: 'confirm' } }), /thesis.name must be a non-empty/],
    [action({ thesis: { name: 'n', claim: 'c', rule: 'r', result: 'maybe' } }), /thesis.result "maybe" is not valid/],
    [extras({ c2_ips: undefined, c2_domain: undefined }), /must set c2_ips, c2_domain, or killed/],
    [extras({ c2_ips: [] }), /c2_ips must be a non-empty/],
    [extras({ c2_ips: [''] }), /c2_ips\[0\] must be a non-empty/],
    [extras({ c2_domain: '' }), /c2_domain must be a non-empty/],
    [extras({ killed: [] }), /killed must be a non-empty/],
    [extras({ killed: [''] }), /killed\[0\] must be a non-empty/],
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
