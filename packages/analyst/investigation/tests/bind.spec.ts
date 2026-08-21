import { describe, expect, it } from 'vitest'
import {
  caseReportDenyReason, citesConversation, defaultRoleForAddr, foldBind, formatRolesCard,
  identityDonatesToVictim, isCueObservationAddr, projectCaseReport, projectVictimSlot,
  resolveBind, roleForIdentity, UNBOUND_REASON, victimOf, VICTIM_COUNT_REASON,
} from '../src/bind.ts'
import { formatLedger } from '../src/ledger.ts'
import { identityOf } from '../src/harvest.ts'
import type { Identity, Relationship, RelationshipBind } from '../src/types.ts'

const LAN = '10.0.10.2'
const C2 = '198.51.100.80'
const DISTRACTOR = '10.0.10.3'
const CLIENT_MAC = '02:00:00:00:00:0a'
const DISTRACTOR_MAC = '02:00:00:00:00:0b'
const HOST = 'lan-host'
const DISTRACTOR_HOST = 'idle-host'
const USER = 'lan-user'

const relationship: Relationship = {
  src: LAN,
  dst: C2,
  dport: 443,
  t: '2026-08-21T00:00:00Z',
  evidence_id: 'conv-1',
}

const conversationBecause = `${LAN} talking to ${C2} in evidence conv-1`

function bind(over: Partial<RelationshipBind> = {}): RelationshipBind {
  return {
    relationship,
    endpoints: [
      { addr: LAN, role: 'victim', because: conversationBecause },
      { addr: C2, role: 'c2', because: 'cue/observation address' },
    ],
    ...over,
  }
}

describe('BindRelationship', () => {
  it('defaults a cue/external IP to c2 and requires exactly one victim', () => {
    expect(isCueObservationAddr(C2)).toBe(true)
    expect(isCueObservationAddr(LAN)).toBe(false)
    expect(defaultRoleForAddr(C2)).toBe('c2')
    expect(defaultRoleForAddr(LAN)).toBe('unknown')
    const completed = resolveBind({
      relationship,
      endpoints: [{ addr: LAN, role: 'victim', because: conversationBecause }],
    })
    expect(completed).toEqual({
      ok: true,
      bind: {
        relationship,
        endpoints: [
          { addr: LAN, role: 'victim', because: conversationBecause },
          { addr: C2, role: 'c2', because: 'cue/observation address' },
        ],
      },
    })
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, because: 'alert named this host' }],
    }).ok).toBe(false)
    expect(resolveBind({
      relationship,
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: DISTRACTOR, role: 'victim', because: conversationBecause },
      ],
    })).toEqual({ ok: false, reason: VICTIM_COUNT_REASON })
    expect(resolveBind({
      relationship,
      endpoints: [
        { addr: LAN, role: 'unknown', because: 'not yet' },
        { addr: C2, role: 'c2', because: 'cue' },
      ],
    })).toEqual({ ok: false, reason: VICTIM_COUNT_REASON })
  })

  it('denies flipping the cue IP to victim without a conversation-cited because', () => {
    expect(citesConversation('the alert named this IP', relationship)).toBe(false)
    expect(citesConversation(conversationBecause, relationship)).toBe(true)
    expect(citesConversation('packet flow on port 443', relationship)).toBe(true)
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: 'the alert named this IP' }],
    })).toEqual({ ok: false, reason: UNBOUND_REASON })
    const flipped = resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })
    expect(flipped.ok).toBe(true)
    if (!flipped.ok) throw new Error('expected a conversation-cited flip to succeed')
    expect(victimOf(flipped.bind)?.addr).toBe(C2)
  })

  it('projects who/where from the victim row and refuses distractor donation', () => {
    const victimIp = identityOf('ip', LAN)!
    const c2Ip = identityOf('ip', C2)!
    const victimMac: Identity = { ...identityOf('mac', CLIENT_MAC)!, entity_id: LAN }
    const distractorMac: Identity = { ...identityOf('mac', DISTRACTOR_MAC)!, entity_id: DISTRACTOR }
    const victimHost: Identity = { ...identityOf('hostname', HOST)!, entity_id: LAN }
    const distractorHost: Identity = { ...identityOf('hostname', DISTRACTOR_HOST)!, entity_id: DISTRACTOR }
    const victimUser: Identity = { ...identityOf('user', USER)!, entity_id: LAN }
    const distractorUser: Identity = {
      ...identityOf('user', 'idle-user')!,
      entity_id: DISTRACTOR,
      evidence_id: DISTRACTOR,
    }
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle LAN workstation' },
      ],
    })
    const identities = [
      victimIp, c2Ip, victimMac, distractorMac, victimHost, distractorHost, victimUser, distractorUser,
    ]
    const conversation = `${LAN} → ${C2} TCP`
    expect(identityDonatesToVictim(victimMac, live, identities, conversation)).toBe(true)
    expect(identityDonatesToVictim(distractorMac, live, identities, conversation)).toBe(false)
    expect(identityDonatesToVictim(distractorHost, live, identities, conversation)).toBe(false)
    const slot = projectVictimSlot(live, identities, conversation)
    expect(slot).toEqual({
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
    })
    expect(slot?.mac).not.toBe(DISTRACTOR_MAC)
    expect(slot?.hostname).not.toBe(DISTRACTOR_HOST)
    const report = projectCaseReport(live, identities, {
      what: 'beacon', when: '2026-08-21', why: 'c2', how: 'https',
    }, conversation)
    expect(report?.who).toEqual(slot)
    expect(report?.where).toEqual(slot)
    expect(roleForIdentity(c2Ip, live, identities)).toBe('c2')
    expect(roleForIdentity(distractorHost, live, identities)).toBe('distractor')
  })

  it('denies case_report when unbound, inverted, or given free-text who/where', () => {
    const live = bind()
    expect(caseReportDenyReason({ what: 'x' }, undefined)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: C2, where: C2 }, live)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: { entity_id: C2 } }, live)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ where: { entity_id: DISTRACTOR } }, live)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: { evidence_id: C2 } }, live)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ what: 'x' }, live)).toBeUndefined()
    expect(caseReportDenyReason({ who: { entity_id: LAN } }, live)).toBeUndefined()
    expect(foldBind([])).toBeUndefined()
    expect(foldBind([
      { type: 'investigation/bind', data: bind() },
      { type: 'investigation/bind', data: bind({ relationship: { ...relationship, evidence_id: 'conv-2' } }) },
    ])?.relationship.evidence_id).toBe('conv-2')
    expect(formatRolesCard(bind())).toContain('victim 10.0.10.2')
    expect(formatRolesCard(bind())).toContain('c2 198.51.100.80')
    expect(formatLedger([], [], undefined)).toBe('')
    expect(formatLedger([identityOf('ip', LAN)!], [], undefined, bind())).toContain('[victim] IP')
    expect(formatLedger([], [], { who: { entity_id: LAN } })).toContain('case_report')
  })

  it('rejects incomplete relationship fields and a duplicated endpoint', () => {
    expect(resolveBind({
      relationship: { ...relationship, src: '  ' },
      endpoints: [{ addr: LAN, role: 'victim', because: conversationBecause }],
    }).ok).toBe(false)
    expect(resolveBind({
      relationship: { ...relationship, dport: 0 },
      endpoints: [{ addr: LAN, role: 'victim', because: conversationBecause }],
    }).ok).toBe(false)
    expect(resolveBind({
      relationship: { ...relationship, evidence_id: '' },
      endpoints: [{ addr: LAN, role: 'victim', because: conversationBecause }],
    }).ok).toBe(false)
    expect(resolveBind({
      relationship,
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: LAN, role: 'c2', because: conversationBecause },
      ],
    }).ok).toBe(false)
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: '', role: 'victim', because: conversationBecause }],
    }).ok).toBe(false)
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: LAN, role: 'victim', because: '   ' }],
    }).ok).toBe(false)
    expect(resolveBind({
      relationship: { ...relationship, t: '' },
      endpoints: [{ addr: LAN, role: 'victim', because: conversationBecause }],
    }).ok).toBe(false)
    expect(resolveBind({
      relationship: { ...relationship, dport: 65536 },
      endpoints: [{ addr: LAN, role: 'victim', because: conversationBecause }],
    }).ok).toBe(false)
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: LAN, role: 'not-a-role' as 'victim', because: conversationBecause }],
    }).ok).toBe(false)
    expect(citesConversation(`${LAN}:${443} peer`, relationship)).toBe(true)
    expect(caseReportDenyReason('x', bind())).toBeUndefined()
    expect(caseReportDenyReason({ who: 1 }, bind())).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: { entity_id: 1 } }, bind())).toBe(UNBOUND_REASON)
    const noVictim = { ...bind(), endpoints: [{ addr: C2, role: 'c2' as const, because: 'cue' }] }
    expect(identityDonatesToVictim(identityOf('ip', LAN)!, noVictim, [])).toBe(false)
    expect(projectVictimSlot(noVictim, [])).toBeUndefined()
    expect(projectCaseReport(noVictim, [], { what: 'a', when: 'b', why: 'c', how: 'd' })).toBeUndefined()
    const mixed = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue' },
        { addr: '10.0.10.4', role: 'infra', because: 'gateway' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle' },
        { addr: '10.0.10.8', role: 'unknown', because: 'other' },
      ],
    })
    expect(formatRolesCard(mixed)).toContain('infra 10.0.10.4')
    const tagged: Identity = { ...identityOf('hostname', HOST)!, entity_id: LAN, evidence_id: DISTRACTOR }
    expect(identityDonatesToVictim(tagged, bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle' },
      ],
    }), [tagged])).toBe(false)
    expect(roleForIdentity(identityOf('mac', CLIENT_MAC)!, bind(), [identityOf('ip', LAN)!])).toBeUndefined()
    const uniqueMac = identityOf('mac', CLIENT_MAC)!
    const conversation = `${LAN} → ${C2} TCP`
    expect(identityDonatesToVictim(uniqueMac, bind(), [identityOf('ip', LAN)!, uniqueMac], conversation)).toBe(true)
    expect(identityDonatesToVictim(identityOf('hostname', HOST)!, bind(), [])).toBe(false)
    expect(identityDonatesToVictim(identityOf('user', USER)!, bind(), [])).toBe(false)
    const flipped = bind({
      endpoints: [
        { addr: C2, role: 'victim', because: conversationBecause },
        { addr: LAN, role: 'c2', because: 'other end' },
      ],
    })
    expect(identityDonatesToVictim(uniqueMac, flipped, [identityOf('ip', LAN)!, uniqueMac], conversation)).toBe(false)
    expect(caseReportDenyReason({ who: { evidence_id: 'conv-1' } }, bind())).toBeUndefined()
    const foreign: Identity = { ...identityOf('hostname', HOST)!, entity_id: C2, evidence_id: 'slot-c2' }
    expect(caseReportDenyReason({ who: { evidence_id: 'slot-c2' } }, bind(), [foreign])).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: { evidence_id: LAN } }, bind())).toBeUndefined()
  })
})
