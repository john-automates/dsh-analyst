import { describe, expect, it } from 'vitest'
import {
  acceptedC2Domain, BOTH_LAN_CONVERSATION_REASON, caseReportDenyReason, c2DomainHuntForBind,
  completeAcceptedSlot, cueVictimUnboundReason, defaultRoleForAddr, ENDPOINTS_ARRAY_REASON, foldBind,
  formatRolesCard, identityDonatesToVictim, isCueObservationAddr, LAN_C2_REASON,
  normalizeEndpointAddr, otherEndHuntForDeniedBind, projectCaseReport, projectVictimSlot,
  requireCaseReport, resolveBind, roleForIdentity, UNBOUND_REASON, VICTIM_COUNT_REASON,
} from '../src/bind.ts'
import { formatLedger } from '../src/ledger.ts'
import { harvestIdentities, identityOf } from '../src/harvest.ts'
import type { Identity, Relationship, RelationshipBind } from '../src/types.ts'

const LAN = '10.0.10.2'
const LAN_CIDR = '10.0.10.0/24'
const OTHER_CIDR = '172.16.0.0/12'
const C2 = '198.51.100.80'
const DISTRACTOR = '10.0.10.3'
const CLIENT_MAC = '02:00:00:00:00:0a'
const DISTRACTOR_MAC = '02:00:00:00:00:0b'
const HOST = 'lan-host'
const DISTRACTOR_HOST = 'idle-host'
const USER = 'lan-user'
const FULL_NAME = 'Lan User'
const DISTRACTOR_USER = 'idle-user'

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
    expect(isCueObservationAddr(HOST)).toBe(false)
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

  it('denies assigning victim to a cue/observation address', () => {
    const denied = (because: string) => resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because }],
    })
    const cueReason = cueVictimUnboundReason(C2)
    expect(cueReason).toBe(`unbound: hunt LAN ip.src talking to ${C2} (ip.dst == ${C2}).`)
    expect(denied('the alert named this IP')).toEqual({ ok: false, reason: cueReason })
    expect(denied(conversationBecause)).toEqual({ ok: false, reason: cueReason })
    expect(denied('evidence conv-1')).toEqual({ ok: false, reason: cueReason })
    expect(denied(`${LAN} ${C2}`)).toEqual({ ok: false, reason: cueReason })
    expect(denied('dport 443')).toEqual({ ok: false, reason: cueReason })
    expect(otherEndHuntForDeniedBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ kind: 'other-end', subjectKind: 'ip', subject: C2 })
    expect(otherEndHuntForDeniedBind({
      relationship,
      endpoints: [{ addr: LAN, role: 'victim', because: conversationBecause }],
    })).toBeUndefined()
    const live = resolveBind({
      relationship,
      endpoints: [{ addr: LAN, role: 'victim', because: conversationBecause }],
    })
    expect(live).toEqual({
      ok: true,
      bind: {
        relationship,
        endpoints: [
          { addr: LAN, role: 'victim', because: conversationBecause },
          { addr: C2, role: 'c2', because: 'cue/observation address' },
        ],
      },
    })
    if (!live.ok) throw new Error('expected LAN victim to bind')
    expect(c2DomainHuntForBind(live.bind)).toEqual({
      kind: 'c2-domain', subjectKind: 'ip', subject: C2,
    })
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    expect(caseReportDenyReason({ what: 'x' }, live.bind)).toBeUndefined()
    expect(requireCaseReport(live.bind, [], claims)).toEqual({
      who: { entity_id: LAN, ip: LAN },
      what: 'a',
      when: 'b',
      where: { entity_id: LAN, ip: LAN },
      why: 'c',
      how: 'd',
    })
  })

  it('projects who/where from the victim row and refuses distractor donation', () => {
    const victimIp = identityOf('ip', LAN)!
    const c2Ip = identityOf('ip', C2)!
    const victimMac: Identity = { ...identityOf('mac', CLIENT_MAC)!, entity_id: LAN }
    const distractorMac: Identity = { ...identityOf('mac', DISTRACTOR_MAC)!, entity_id: DISTRACTOR }
    const victimHost: Identity = { ...identityOf('hostname', HOST)!, entity_id: LAN }
    const distractorHost: Identity = { ...identityOf('hostname', DISTRACTOR_HOST)!, entity_id: DISTRACTOR }
    const victimUser: Identity = { ...identityOf('user', USER)!, entity_id: LAN }
    const victimName: Identity = { ...identityOf('full_name', FULL_NAME)!, entity_id: LAN }
    const distractorUser: Identity = {
      ...identityOf('user', DISTRACTOR_USER)!,
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
      victimIp, c2Ip, victimMac, distractorMac, victimHost, distractorHost, victimUser, victimName,
      distractorUser,
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
      full_name: FULL_NAME,
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

  it('persists a C2-stamped DNS name as c2_domain and does not donate it to who/where', () => {
    const DOMAIN = 'c2.example.test'
    const live = bind()
    const victimHost: Identity = { ...identityOf('hostname', HOST)!, entity_id: LAN, evidence_id: LAN }
    const dcHost: Identity = {
      ...identityOf('hostname', 'dc01')!,
      evidence_id: DISTRACTOR,
    }
    const c2Host: Identity = {
      ...identityOf('hostname', DOMAIN)!,
      evidence_id: C2,
    }
    const lanOnC2: Identity = {
      ...identityOf('hostname', 'desktop-lan')!,
      evidence_id: C2,
    }
    const identities = [
      identityOf('ip', LAN)!,
      identityOf('ip', C2)!,
      victimHost,
      dcHost,
      c2Host,
      lanOnC2,
    ]
    expect(acceptedC2Domain(live, identities)).toBe(DOMAIN)
    expect(identityDonatesToVictim(c2Host, live, identities)).toBe(false)
    expect(identityDonatesToVictim(dcHost, live, identities)).toBe(false)
    const slot = projectVictimSlot(live, identities)
    expect(slot).toEqual({ entity_id: LAN, ip: LAN, hostname: HOST })
    expect(slot?.hostname).not.toBe(DOMAIN)
    expect(slot?.hostname).not.toBe('dc01')
    const report = requireCaseReport(live, identities, {
      what: 'beacon', when: '2026-08-21', why: 'c2', how: 'https',
    })
    expect(report.c2_domain).toBe(DOMAIN)
    expect(report.who).toEqual(slot)
    expect(report.where).toEqual(slot)
    expect(report.who.hostname).toBe(HOST)
    expect(report.where.hostname).toBe(HOST)
    expect(acceptedC2Domain(live, [victimHost, dcHost, lanOnC2])).toBeUndefined()
    expect(requireCaseReport(live, [identityOf('ip', LAN)!, victimHost], {
      what: 'a', when: 'b', why: 'c', how: 'd',
    }).c2_domain).toBeUndefined()
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

  it('coerces a JSON-string endpoints list and numeric-string dport before resolveBind', () => {
    const endpoints = [{ addr: LAN, role: 'victim' as const, because: conversationBecause }]
    const native = resolveBind({ relationship, endpoints })
    expect(resolveBind({
      relationship: { ...relationship, dport: '443' },
      endpoints: JSON.stringify(endpoints),
    })).toEqual(native)
    expect(native).toEqual({
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
      relationship: { ...relationship, dport: '443' },
      endpoints: JSON.stringify([{ addr: C2, role: 'victim', because: 'the alert named this IP' }]),
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    expect(otherEndHuntForDeniedBind({
      relationship: { ...relationship, dport: '443' },
      endpoints: JSON.stringify([{ addr: C2, role: 'victim', because: conversationBecause }]),
    })).toEqual({ kind: 'other-end', subjectKind: 'ip', subject: C2 })
    expect(resolveBind({
      relationship,
      endpoints: JSON.stringify({ addr: LAN, role: 'victim', because: conversationBecause }),
    })).toEqual({ ok: false, reason: ENDPOINTS_ARRAY_REASON })
    expect(resolveBind({
      relationship,
      endpoints: 'not-a-json-array',
    })).toEqual({ ok: false, reason: ENDPOINTS_ARRAY_REASON })
    expect(otherEndHuntForDeniedBind({
      relationship,
      endpoints: 'not-a-json-array',
    })).toBeUndefined()
    expect(resolveBind({
      relationship: { src: LAN, dst: C2, t: relationship.t, evidence_id: relationship.evidence_id },
      endpoints,
    }).ok).toBe(false)
    expect(resolveBind({
      relationship: { ...relationship, dport: '0' },
      endpoints,
    }).ok).toBe(false)
    expect(resolveBind({
      relationship: { ...relationship, dport: '65536' },
      endpoints,
    }).ok).toBe(false)
    expect(resolveBind({
      relationship: { ...relationship, dport: '443.5' },
      endpoints,
    }).ok).toBe(false)
  })

  it('denies a both-LAN conversation and a LAN c2 without inventing a C2 hunt', () => {
    const dcRelationship: Relationship = {
      src: LAN,
      dst: DISTRACTOR,
      dport: 88,
      t: relationship.t,
      evidence_id: 'conv-dc',
    }
    const dcBecause = `${LAN} talking to ${DISTRACTOR} in evidence conv-dc`
    const dcEndpoints = [
      { addr: LAN, role: 'victim' as const, because: dcBecause },
      { addr: DISTRACTOR, role: 'c2' as const, because: dcBecause },
    ]
    expect(resolveBind({
      relationship: dcRelationship,
      endpoints: dcEndpoints,
    })).toEqual({ ok: false, reason: BOTH_LAN_CONVERSATION_REASON })
    expect(BOTH_LAN_CONVERSATION_REASON).toBe(
      'unbound: cite the LAN host talking to the cue/observation address, not a LAN DC/AD service.',
    )
    expect(BOTH_LAN_CONVERSATION_REASON).not.toContain(C2)
    expect(otherEndHuntForDeniedBind({
      relationship: dcRelationship,
      endpoints: dcEndpoints,
    })).toBeUndefined()
    const lanC2 = {
      relationship: dcRelationship,
      endpoints: [
        { addr: LAN, role: 'victim' as const, because: dcBecause },
        { addr: DISTRACTOR, role: 'c2' as const, because: dcBecause },
      ],
    }
    expect(c2DomainHuntForBind(lanC2)).toBeUndefined()
    expect(acceptedC2Domain(lanC2, [])).toBeUndefined()
    expect(otherEndHuntForDeniedBind({
      relationship: dcRelationship,
      endpoints: [{ addr: C2, role: 'victim', because: 'the alert named this IP' }],
    })).toBeUndefined()
    expect(resolveBind({
      relationship: { ...dcRelationship, dport: '88' },
      endpoints: JSON.stringify(dcEndpoints),
    })).toEqual({ ok: false, reason: BOTH_LAN_CONVERSATION_REASON })
    expect(otherEndHuntForDeniedBind({
      relationship: { ...dcRelationship, dport: '88' },
      endpoints: JSON.stringify(dcEndpoints),
    })).toBeUndefined()
    expect(resolveBind({
      relationship,
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: DISTRACTOR, role: 'c2', because: 'LAN DC' },
      ],
    })).toEqual({ ok: false, reason: LAN_C2_REASON })
    expect(otherEndHuntForDeniedBind({
      relationship,
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: DISTRACTOR, role: 'c2', because: 'LAN DC' },
      ],
    })).toBeUndefined()
    const live = resolveBind({
      relationship,
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
      ],
    })
    expect(live).toEqual({
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
      relationship: { ...relationship, dport: '443' },
      endpoints: JSON.stringify([{ addr: LAN, role: 'victim', because: conversationBecause }]),
    })).toEqual(live)
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    expect(otherEndHuntForDeniedBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ kind: 'other-end', subjectKind: 'ip', subject: C2 })
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
    expect(normalizeEndpointAddr('LAN-HOST')).toBe('lan-host')
    expect(projectVictimSlot(bind(), [])).toEqual({ entity_id: LAN, ip: LAN })
    expect(projectVictimSlot(bind({
      endpoints: [
        { addr: HOST, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue' },
      ],
    }), [])).toEqual({ entity_id: HOST })
    expect(caseReportDenyReason('x', bind())).toBeUndefined()
    expect(caseReportDenyReason({ who: 1 }, bind())).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: { entity_id: 1 } }, bind())).toBe(UNBOUND_REASON)
    const noVictim = { ...bind(), endpoints: [{ addr: C2, role: 'c2' as const, because: 'cue' }] }
    expect(identityDonatesToVictim(
      { ...identityOf('ip', LAN)!, evidence_id: 'slot-x' },
      noVictim,
      [],
    )).toBe(false)
    expect(identityDonatesToVictim(identityOf('ip', LAN)!, noVictim, [])).toBe(false)
    expect(projectVictimSlot(noVictim, [])).toBeUndefined()
    expect(projectCaseReport(noVictim, [], { what: 'a', when: 'b', why: 'c', how: 'd' })).toBeUndefined()
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    expect(() => requireCaseReport(undefined, [], claims)).toThrow(UNBOUND_REASON)
    expect(() => requireCaseReport(noVictim, [], claims)).toThrow(UNBOUND_REASON)
    expect(requireCaseReport(bind(), [], claims)).toEqual({
      who: { entity_id: LAN, ip: LAN },
      what: 'a',
      when: 'b',
      where: { entity_id: LAN, ip: LAN },
      why: 'c',
      how: 'd',
    })
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

  it('closes case_report when who.entity_id is the victim-row user', () => {
    const live = bind()
    const identities = [
      identityOf('ip', LAN)!,
      { ...identityOf('user', USER)!, entity_id: LAN },
    ]
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    expect(caseReportDenyReason({
      who: { entity_id: USER },
      where: { entity_id: LAN },
    }, undefined, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: { entity_id: C2 } }, live, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: { entity_id: '   ' } }, live, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({
      who: { entity_id: USER },
      where: { entity_id: LAN },
    }, live, identities)).toBeUndefined()
    expect(caseReportDenyReason({
      who: JSON.stringify({ entity_id: USER }),
      where: JSON.stringify({ entity_id: LAN }),
    }, live, identities)).toBeUndefined()
    expect(caseReportDenyReason({
      who: `{"entity_id":"${C2}"}`,
    }, live, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: '{not-json' }, live, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ where: { entity_id: USER } }, live, identities)).toBeUndefined()
    const report = requireCaseReport(live, identities, claims)
    expect(report.who).toEqual({ entity_id: LAN, ip: LAN, user: USER })
    expect(report.where).toEqual({ entity_id: LAN, ip: LAN, user: USER })
  })

  it('closes case_report when who/where are victim-row handle strings after a live bind', () => {
    const live = bind()
    const identities = [
      identityOf('ip', LAN)!,
      { ...identityOf('user', USER)!, entity_id: LAN },
      { ...identityOf('full_name', FULL_NAME)!, entity_id: LAN },
      { ...identityOf('hostname', HOST)!, entity_id: LAN },
      { ...identityOf('user', DISTRACTOR_USER)!, entity_id: DISTRACTOR },
    ]
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const projected = { entity_id: LAN, ip: LAN, hostname: HOST, user: USER, full_name: FULL_NAME }
    expect(caseReportDenyReason({
      who: USER,
      where: LAN,
    }, undefined, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: USER }, live, identities)).toBeUndefined()
    expect(caseReportDenyReason({ who: `${USER} (${FULL_NAME})` }, live, identities)).toBeUndefined()
    expect(caseReportDenyReason({ where: LAN }, live, identities)).toBeUndefined()
    expect(caseReportDenyReason({ where: `${LAN} (${HOST})` }, live, identities)).toBeUndefined()
    expect(caseReportDenyReason({
      who: `${USER} (${FULL_NAME})`,
      where: `${LAN} (${HOST})`,
    }, live, identities)).toBeUndefined()
    expect(caseReportDenyReason({ who: C2 }, live, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ where: DISTRACTOR_USER }, live, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: 'the workstation on the LAN' }, live, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: DISTRACTOR }, live, identities)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: ' () ' }, live, identities)).toBe(UNBOUND_REASON)
    const report = requireCaseReport(live, identities, claims)
    expect(report.who).toEqual(projected)
    expect(report.where).toEqual(projected)
  })

  it('coerces labeled and sentence who/where strings onto the victim after a live bind', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const dcDonated = {
      ...identityOf('mac', CLIENT_MAC)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const dcMac = { ...identityOf('mac', DISTRACTOR_MAC)!, evidence_id: DISTRACTOR }
    const victimHost = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const dcHost = { ...identityOf('hostname', HOST)!, entity_id: DISTRACTOR }
    const victimName = identityOf('full_name', FULL_NAME)!
    const dcName = { ...identityOf('full_name', FULL_NAME)!, entity_id: DISTRACTOR }
    const victimUser = {
      ...identityOf('user', USER)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const stampedUser = {
      ...identityOf('user', 'stamp-user')!,
      evidence_id: LAN,
      entity_id: DISTRACTOR,
    }
    const distractorUser = {
      ...identityOf('user', DISTRACTOR_USER)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const identities = [
      identityOf('ip', LAN)!, identityOf('ip', C2)!, dcDonated, dcMac, victimHost, dcHost,
      victimName, dcName, victimUser, stampedUser, distractorUser,
    ]
    const frames = [
      `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`,
      `eth.src: ${DISTRACTOR_MAC}\tip.src: ${DISTRACTOR}`,
      `hostname: ${HOST}\tip.addr: ${LAN}`,
    ].join('\n')
    const conversations = [
      `${LAN} → ${DISTRACTOR}  kerberos.CNameString: ${USER}`,
      `ip.src: ${DISTRACTOR}\tkerberos.CNameString: ${DISTRACTOR_USER}`,
    ].join('\n')
    const evidence = `${frames}\n${conversations}`
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const labeledWho = `User Account: ${USER} / Full Name: ${FULL_NAME} / MAC Address: ${CLIENT_MAC}`
    const labeledWhoWithHost = `${labeledWho} / Hostname: ${HOST}`
    const sentenceWhere = `The infected host was identified as ${HOST} (${LAN})`
    const quotedWhere = `The infected host was identified as ${LAN}, hostname "${HOST}"`
    const quotedWhereSingle = `The infected host was identified as ${LAN}, hostname '${HOST}'`
    expect(identityDonatesToVictim(dcDonated, live, identities, evidence)).toBe(false)
    expect(identityDonatesToVictim(victimUser, live, identities, evidence)).toBe(false)
    expect(caseReportDenyReason({
      who: labeledWho,
      where: sentenceWhere,
    }, undefined, identities, evidence)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: labeledWho }, live, identities, evidence)).toBeUndefined()
    expect(caseReportDenyReason({
      who: `User Account: ${USER} / Full Name: ${FULL_NAME} / MAC Address: ${CLIENT_MAC.replace(/:/g, '-')}`,
    }, live, identities, evidence)).toBeUndefined()
    expect(caseReportDenyReason({ who: labeledWhoWithHost }, live, identities, evidence)).toBeUndefined()
    expect(caseReportDenyReason({ where: sentenceWhere }, live, identities, evidence)).toBeUndefined()
    expect(caseReportDenyReason({ where: quotedWhere }, live, identities, evidence)).toBeUndefined()
    expect(caseReportDenyReason({ where: quotedWhereSingle }, live, identities, evidence)).toBeUndefined()
    expect(caseReportDenyReason({
      who: labeledWho,
      where: quotedWhere,
    }, live, identities, evidence)).toBeUndefined()
    expect(caseReportDenyReason({ who: `${labeledWho} / ${C2}` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: `${labeledWho} / ${DISTRACTOR_MAC}` }, live, identities, evidence))
      .toBeUndefined()
    expect(caseReportDenyReason({ where: `${sentenceWhere} talking to ${C2}` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ where: `${sentenceWhere} / ${DISTRACTOR_MAC}` }, live, identities, evidence))
      .toBeUndefined()
    expect(caseReportDenyReason({ where: `${quotedWhere} talking to ${C2}` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ where: `${quotedWhere} / ${DISTRACTOR_MAC}` }, live, identities, evidence))
      .toBeUndefined()
    expect(caseReportDenyReason({ who: `${labeledWho} / ${DISTRACTOR_USER}` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ where: `${sentenceWhere} / ${DISTRACTOR}` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: `${labeledWho} leftover` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: DISTRACTOR_MAC }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: 'the workstation on the LAN' }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: ' () ' }, live, identities, evidence)).toBe(UNBOUND_REASON)
    const report = requireCaseReport(live, identities, claims, evidence, {
      who: `${labeledWho} / ${DISTRACTOR_MAC}`,
      where: `${sentenceWhere} / ${DISTRACTOR_MAC}`,
    })
    expect(report.who).toEqual({
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    })
    expect(report.where).toEqual(report.who)
    expect(report.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(report.who.user).not.toBe(DISTRACTOR_USER)
    expect(report.who).toMatchObject({
      ip: LAN, hostname: HOST,
    })
  })

  it('coerces locator leftovers and a victim-containing CIDR onto the victim after a live bind', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const dcDonated = {
      ...identityOf('mac', CLIENT_MAC)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const dcMac = { ...identityOf('mac', DISTRACTOR_MAC)!, evidence_id: DISTRACTOR }
    const victimUser = {
      ...identityOf('user', USER)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const identities = [
      identityOf('ip', LAN)!, identityOf('ip', C2)!, dcDonated, dcMac, victimUser,
    ]
    const evidence = [
      `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`,
      `eth.src: ${DISTRACTOR_MAC}\tip.src: ${DISTRACTOR}`,
      `${LAN} → ${DISTRACTOR}  kerberos.CNameString: ${USER}`,
    ].join('\n')
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const locatorWho = `Client IP: ${LAN} / MAC Address: ${CLIENT_MAC}`
    const locatorWhere = `The client was located at ${LAN} on the ${LAN_CIDR} network`
    expect(caseReportDenyReason({
      who: locatorWho,
      where: locatorWhere,
    }, undefined, identities, evidence)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({
      who: locatorWho,
      where: locatorWhere,
    }, live, identities, evidence)).toBeUndefined()
    expect(caseReportDenyReason({ who: `${locatorWho} / ${C2}` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ where: `${locatorWhere} / ${OTHER_CIDR}` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: `${locatorWho} leftover` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: `${locatorWho} / ${DISTRACTOR}` }, live, identities, evidence))
      .toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: LAN_CIDR }, live, identities, evidence)).toBe(UNBOUND_REASON)
    expect(caseReportDenyReason({ who: `${locatorWho} / ${DISTRACTOR_MAC}` }, live, identities, evidence))
      .toBeUndefined()
    expect(caseReportDenyReason({ where: `The client was located at ${LAN} on 0.0.0.0/0` }, live, identities, evidence))
      .toBeUndefined()
    const report = requireCaseReport(live, identities, claims, evidence, {
      who: locatorWho,
      where: locatorWhere,
    })
    expect(report.who).toEqual({
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      user: USER,
    })
    expect(report.where).toEqual(report.who)
    expect(report.who.mac).not.toBe(DISTRACTOR_MAC)
  })

  it('completes the victim row from unique unaffiliated ledger identities after a live bind', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle LAN workstation' },
      ],
    })
    const distractorUser = { ...identityOf('user', DISTRACTOR_USER)!, entity_id: DISTRACTOR }
    const identities = [
      identityOf('ip', LAN)!,
      identityOf('mac', CLIENT_MAC)!,
      identityOf('hostname', HOST)!,
      identityOf('user', USER)!,
      identityOf('full_name', FULL_NAME)!,
      distractorUser,
    ]
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const projected = {
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    expect(caseReportDenyReason({ who: { entity_id: USER }, where: { entity_id: LAN } }, live, identities))
      .toBeUndefined()
    const report = requireCaseReport(live, identities, claims)
    expect(report.who).toEqual(projected)
    expect(report.where).toEqual(projected)
    expect(report.who.user).not.toBe(DISTRACTOR_USER)
    expect(identityDonatesToVictim(distractorUser, live, identities)).toBe(false)
    const twoUsers = [...identities, identityOf('user', 'other-user')!]
    const ambiguous = requireCaseReport(live, twoUsers, claims)
    expect(ambiguous.who).toEqual({
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      full_name: FULL_NAME,
    })
    expect(ambiguous.where).toEqual(ambiguous.who)
    expect(ambiguous.who.user).toBeUndefined()
    const affiliatedUser = { ...identityOf('user', USER)!, entity_id: LAN }
    expect(requireCaseReport(live, [identityOf('ip', LAN)!, affiliatedUser, identityOf('user', 'other-user')!], claims).who).toEqual({
      entity_id: LAN,
      ip: LAN,
      user: USER,
    })
  })

  it('donates mac and hostname evidenced on the bound victim IP after a live bind', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle LAN workstation' },
      ],
    })
    const victimMac = identityOf('mac', CLIENT_MAC)!
    const victimHost = identityOf('hostname', HOST)!
    const idleMac = { ...identityOf('mac', DISTRACTOR_MAC)!, entity_id: DISTRACTOR }
    const idleHost = { ...identityOf('hostname', DISTRACTOR_HOST)!, entity_id: DISTRACTOR }
    const scopedDump = [
      `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`,
      `hostname: ${HOST}\tip.addr: ${LAN}`,
    ].join('\n')
    const identities = [identityOf('ip', LAN)!, victimMac, victimHost, idleMac, idleHost]
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const projected = {
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
    }
    expect(identityDonatesToVictim(victimMac, live, identities, scopedDump)).toBe(true)
    expect(identityDonatesToVictim(victimHost, live, identities, scopedDump)).toBe(true)
    expect(identityDonatesToVictim(idleMac, live, identities, scopedDump)).toBe(false)
    expect(identityDonatesToVictim(idleHost, live, identities, scopedDump)).toBe(false)
    const report = requireCaseReport(live, identities, claims, scopedDump)
    expect(report.who).toEqual(projected)
    expect(report.where).toEqual(projected)
    expect(report.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(report.who.hostname).not.toBe(DISTRACTOR_HOST)
    const ledger = formatLedger(
      identities,
      [{ kind: 'eth-src', subjectKind: 'ip', subject: LAN }],
      undefined,
      live,
      scopedDump,
    )
    expect(ledger).toContain(`[victim] MAC ${CLIENT_MAC}`)
    expect(ledger).toContain(`[victim] hostname ${HOST}`)
    expect(ledger).toContain(`[distractor] MAC ${DISTRACTOR_MAC}`)
    expect(ledger).toContain(`[distractor] hostname ${DISTRACTOR_HOST}`)
    const byEvidence = [
      identityOf('ip', LAN)!,
      { ...identityOf('mac', CLIENT_MAC)!, evidence_id: LAN },
      { ...identityOf('hostname', HOST)!, evidence_id: LAN },
      idleMac,
      idleHost,
    ]
    expect(requireCaseReport(live, byEvidence, claims).who).toEqual(projected)
    const twoMacs = [identityOf('ip', LAN)!, identityOf('mac', CLIENT_MAC)!, identityOf('mac', DISTRACTOR_MAC)!]
    const ambiguous = requireCaseReport(live, twoMacs, claims)
    expect(ambiguous.who).toEqual({ entity_id: LAN, ip: LAN })
    expect(ambiguous.who.mac).toBeUndefined()
    const idleLine = identityOf('mac', DISTRACTOR_MAC)!
    const bothLines = [
      `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`,
      `eth.src: ${DISTRACTOR_MAC}\tip.src: ${DISTRACTOR}`,
    ].join('\n')
    expect(identityDonatesToVictim(victimMac, live, [identityOf('ip', LAN)!, victimMac, idleLine], bothLines)).toBe(true)
    expect(identityDonatesToVictim(idleLine, live, [identityOf('ip', LAN)!, victimMac, idleLine], bothLines)).toBe(false)
    expect(roleForIdentity(idleLine, live, [identityOf('ip', LAN)!, victimMac, idleLine], bothLines)).toBe('distractor')
    const conversationOnly = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: 'conv-1' }
    expect(identityDonatesToVictim(conversationOnly, live, [identityOf('ip', LAN)!, conversationOnly, identityOf('mac', DISTRACTOR_MAC)!])).toBe(false)
    const scopedHost = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const extraHost = identityOf('hostname', 'other-host')!
    expect(requireCaseReport(live, [identityOf('ip', LAN)!, scopedHost, extraHost], claims).who).toEqual({
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
    })
  })

  it('donates a MAC first stamped on a DC hunt when later frames source it from the victim IP', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const clientMac = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: DISTRACTOR }
    const dcMac = { ...identityOf('mac', DISTRACTOR_MAC)!, evidence_id: DISTRACTOR }
    const victimHost = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const emptyEntity = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: DISTRACTOR, entity_id: '' }
    const victimEntity = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: DISTRACTOR, entity_id: LAN }
    const otherEntity = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: DISTRACTOR, entity_id: DISTRACTOR }
    const frames = [
      `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`,
      `eth.src: ${DISTRACTOR_MAC}\tip.src: ${DISTRACTOR}`,
    ].join('\n')
    const identities = [identityOf('ip', LAN)!, clientMac, dcMac, victimHost]
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    expect(identityDonatesToVictim(clientMac, live, identities, frames)).toBe(true)
    expect(identityDonatesToVictim(emptyEntity, live, identities, frames)).toBe(true)
    expect(identityDonatesToVictim(victimEntity, live, identities, frames)).toBe(true)
    expect(identityDonatesToVictim(otherEntity, live, identities, frames)).toBe(false)
    expect(identityDonatesToVictim(dcMac, live, identities, frames)).toBe(false)
    const strayA = identityOf('mac', '02:00:00:00:00:0c')!
    const strayB = identityOf('mac', '02:00:00:00:00:0d')!
    expect(identityDonatesToVictim(strayA, live, [identityOf('ip', LAN)!, clientMac, strayA, strayB], frames))
      .toBe(false)
    expect(identityDonatesToVictim(victimHost, live, identities, frames)).toBe(true)
    const report = requireCaseReport(live, identities, claims, frames)
    expect(report.who).toEqual({
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
    })
    expect(report.where).toEqual(report.who)
    expect(report.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(roleForIdentity(clientMac, live, identities, frames)).toBe('victim')
    expect(roleForIdentity(dcMac, live, identities, frames)).toBe('distractor')
  })

  it('donates a user and full_name first seen on a DC hunt when the conversation client is the victim', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const victimUser = { ...identityOf('user', USER)!, evidence_id: DISTRACTOR }
    const victimName = { ...identityOf('full_name', FULL_NAME)!, evidence_id: DISTRACTOR }
    const otherUser = { ...identityOf('user', DISTRACTOR_USER)!, evidence_id: DISTRACTOR }
    const otherName = { ...identityOf('full_name', 'Idle User')!, evidence_id: DISTRACTOR }
    const emptyEntity = { ...identityOf('user', USER)!, evidence_id: DISTRACTOR, entity_id: '' }
    const victimEntity = { ...identityOf('user', USER)!, evidence_id: DISTRACTOR, entity_id: LAN }
    const otherEntity = { ...identityOf('user', USER)!, evidence_id: DISTRACTOR, entity_id: DISTRACTOR }
    const untaggedUser = identityOf('user', USER)!
    const untaggedName = identityOf('full_name', FULL_NAME)!
    const conversations = [
      `${LAN} → ${DISTRACTOR}  kerberos.CNameString: ${USER}`,
      `${LAN} → ${DISTRACTOR}  samr.samr_UserInfo21.full_name: ${FULL_NAME}`,
      `ip.src: ${DISTRACTOR}\tkerberos.CNameString: ${DISTRACTOR_USER}`,
      `ip.src: ${DISTRACTOR}\tsamr.samr_UserInfo21.full_name: Idle User`,
    ].join('\n')
    const identities = [identityOf('ip', LAN)!, victimUser, victimName, otherUser, otherName]
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    expect(identityDonatesToVictim(victimUser, live, identities, conversations)).toBe(true)
    expect(identityDonatesToVictim(victimName, live, identities, conversations)).toBe(true)
    expect(identityDonatesToVictim(emptyEntity, live, identities, conversations)).toBe(true)
    expect(identityDonatesToVictim(victimEntity, live, identities, conversations)).toBe(true)
    expect(identityDonatesToVictim(otherEntity, live, identities, conversations)).toBe(false)
    expect(identityDonatesToVictim(otherUser, live, identities, conversations)).toBe(false)
    expect(identityDonatesToVictim(otherName, live, identities, conversations)).toBe(false)
    const report = requireCaseReport(live, identities, claims, conversations)
    expect(report.who).toEqual({
      entity_id: LAN,
      ip: LAN,
      user: USER,
      full_name: FULL_NAME,
    })
    expect(report.where).toEqual(report.who)
    expect(report.who.user).not.toBe(DISTRACTOR_USER)
    expect(report.who.full_name).not.toBe('Idle User')
    expect(roleForIdentity(victimUser, live, identities, conversations)).toBe('victim')
    expect(roleForIdentity(otherUser, live, identities, conversations)).toBe('distractor')
    const untagged = [identityOf('ip', LAN)!, untaggedUser, untaggedName, otherUser, otherName]
    expect(identityDonatesToVictim(untaggedUser, live, untagged, conversations)).toBe(true)
    expect(identityDonatesToVictim(untaggedName, live, untagged, conversations)).toBe(true)
    expect(identityDonatesToVictim(otherUser, live, untagged, conversations)).toBe(false)
    expect(requireCaseReport(live, untagged, claims, conversations).who).toEqual({
      entity_id: LAN,
      ip: LAN,
      user: USER,
      full_name: FULL_NAME,
    })
    const clientStampedUser = { ...identityOf('user', USER)!, evidence_id: LAN }
    const clientStampedName = { ...identityOf('full_name', FULL_NAME)!, evidence_id: LAN }
    const clientStamped = [identityOf('ip', LAN)!, clientStampedUser, clientStampedName, otherUser, otherName]
    expect(identityDonatesToVictim(clientStampedUser, live, clientStamped, conversations)).toBe(true)
    expect(identityDonatesToVictim(clientStampedName, live, clientStamped, conversations)).toBe(true)
    expect(identityDonatesToVictim(otherUser, live, clientStamped, conversations)).toBe(false)
    expect(requireCaseReport(live, clientStamped, claims, conversations).who).toEqual({
      entity_id: LAN,
      ip: LAN,
      user: USER,
      full_name: FULL_NAME,
    })
    const macFrames = `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`
    const hostScoped = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const clientMac = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: DISTRACTOR }
    expect(requireCaseReport(
      live,
      [identityOf('ip', LAN)!, clientMac, hostScoped, victimUser, victimName, otherUser],
      claims,
      `${macFrames}\n${conversations}`,
    ).who).toEqual({
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    })
    const fieldOnlyUser = { ...identityOf('user', USER)!, evidence_id: LAN }
    const dcUser = { ...identityOf('user', DISTRACTOR_USER)!, evidence_id: DISTRACTOR }
    const fieldOnlyDump = [
      `${LAN} → ${DISTRACTOR}`,
      `kerberos.CNameString: ${USER}`,
      `ip.src: ${DISTRACTOR}\tkerberos.CNameString: ${DISTRACTOR_USER}`,
    ].join('\n')
    const fieldOnlyLedger = [identityOf('ip', LAN)!, fieldOnlyUser, dcUser]
    expect(identityDonatesToVictim(fieldOnlyUser, live, fieldOnlyLedger, fieldOnlyDump)).toBe(true)
    expect(identityDonatesToVictim(dcUser, live, fieldOnlyLedger, fieldOnlyDump)).toBe(false)
    expect(requireCaseReport(live, fieldOnlyLedger, claims, fieldOnlyDump).who).toEqual({
      entity_id: LAN,
      ip: LAN,
      user: USER,
    })
    expect(requireCaseReport(live, fieldOnlyLedger, claims, fieldOnlyDump).where).toEqual({
      entity_id: LAN,
      ip: LAN,
      user: USER,
    })
    const untaggedFieldOnly = identityOf('user', USER)!
    const untaggedLedger = [identityOf('ip', LAN)!, untaggedFieldOnly, dcUser]
    expect(identityDonatesToVictim(untaggedFieldOnly, live, untaggedLedger, fieldOnlyDump)).toBe(true)
    expect(requireCaseReport(live, untaggedLedger, claims, fieldOnlyDump).who.user).toBe(USER)
  })

  it('persists a victim-sourced MAC when case_report who/where omit that key', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const clientMac = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: LAN }
    const dcMac = { ...identityOf('mac', DISTRACTOR_MAC)!, evidence_id: DISTRACTOR }
    const victimHost = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const victimUser = identityOf('user', USER)!
    const victimName = identityOf('full_name', FULL_NAME)!
    const identities = [identityOf('ip', LAN)!, clientMac, dcMac, victimHost, victimUser, victimName]
    const frames = [
      `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`,
      `eth.src: ${DISTRACTOR_MAC}\tip.src: ${DISTRACTOR}`,
    ].join('\n')
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const omittedMac = {
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    expect(caseReportDenyReason({ who: omittedMac, where: omittedMac }, live, identities, frames))
      .toBeUndefined()
    const projected = {
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    const report = requireCaseReport(live, identities, claims, frames, {
      who: omittedMac,
      where: JSON.stringify(omittedMac),
    })
    expect(report.who).toEqual(projected)
    expect(report.where).toEqual(projected)
    expect(report.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(report.where.mac).not.toBe(DISTRACTOR_MAC)
    expect(completeAcceptedSlot(projected, { ...omittedMac, mac: DISTRACTOR_MAC })).toEqual(projected)
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, { mac: DISTRACTOR_MAC })).toEqual({
      entity_id: LAN,
      ip: LAN,
    })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, USER)).toEqual({ entity_id: LAN, ip: LAN })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, '{not-json')).toEqual({
      entity_id: LAN,
      ip: LAN,
    })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, '[]')).toEqual({ entity_id: LAN, ip: LAN })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, [])).toEqual({ entity_id: LAN, ip: LAN })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, null)).toEqual({ entity_id: LAN, ip: LAN })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, { mac: '   ' })).toEqual({
      entity_id: LAN,
      ip: LAN,
    })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, { mac: 1 })).toEqual({
      entity_id: LAN,
      ip: LAN,
    })
    const noVictimMac = [identityOf('ip', LAN)!, dcMac, victimHost, victimUser, victimName]
    const withoutMac = requireCaseReport(live, noVictimMac, claims, frames, { who: omittedMac })
    expect(withoutMac.who).toEqual({
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    })
    expect(withoutMac.who.mac).toBeUndefined()
    expect(withoutMac.where.mac).toBeUndefined()
  })

  it('restamps a field-only victim-IP eth.src dump onto who/where after a live bind', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const firstHarvest = identityOf('mac', CLIENT_MAC)!
    expect(firstHarvest.evidence_id).toBeUndefined()
    const victimScoped = harvestIdentities(`eth.src: ${CLIENT_MAC}`, `eth.src: ${CLIENT_MAC}`, LAN)
      .find(item => item.kind === 'mac')
    expect(victimScoped).toEqual({ kind: 'mac', value: CLIENT_MAC, label: 'MAC', evidence_id: LAN })
    const dcScoped = harvestIdentities(`eth.src: ${DISTRACTOR_MAC}`, `eth.src: ${DISTRACTOR_MAC}`, DISTRACTOR)
      .find(item => item.kind === 'mac')
    expect(dcScoped).toEqual({
      kind: 'mac', value: DISTRACTOR_MAC, label: 'MAC', evidence_id: DISTRACTOR,
    })
    const restamped = { ...firstHarvest, evidence_id: LAN }
    const victimHost = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const victimUser = identityOf('user', USER)!
    const victimName = identityOf('full_name', FULL_NAME)!
    const identities = [
      identityOf('ip', LAN)!,
      restamped,
      dcScoped!,
      victimHost,
      victimUser,
      victimName,
    ]
    const fieldOnlyDumps = [`eth.src: ${CLIENT_MAC}`, `eth.src: ${DISTRACTOR_MAC}`].join('\n')
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const omittedMac = {
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    expect(identityDonatesToVictim(restamped, live, identities, fieldOnlyDumps)).toBe(true)
    expect(identityDonatesToVictim(dcScoped!, live, identities, fieldOnlyDumps)).toBe(false)
    const projected = {
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    const report = requireCaseReport(live, identities, claims, fieldOnlyDumps, {
      who: omittedMac,
      where: omittedMac,
    })
    expect(report.who).toEqual(projected)
    expect(report.where).toEqual(projected)
    expect(report.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(report.where.mac).not.toBe(DISTRACTOR_MAC)
    const strayA = identityOf('mac', '02:00:00:00:00:0c')!
    const strayB = identityOf('mac', '02:00:00:00:00:0d')!
    const threeUnaffiliated = [identityOf('ip', LAN)!, firstHarvest, strayA, strayB]
    expect(identityDonatesToVictim(firstHarvest, live, threeUnaffiliated, `eth.src: ${CLIENT_MAC}`))
      .toBe(false)
    expect(requireCaseReport(live, threeUnaffiliated, claims, `eth.src: ${CLIENT_MAC}`).who.mac)
      .toBeUndefined()
    expect(identityDonatesToVictim(
      restamped,
      live,
      [identityOf('ip', LAN)!, restamped, strayA, strayB],
      fieldOnlyDumps,
    )).toBe(true)
    expect(requireCaseReport(
      live,
      [identityOf('ip', LAN)!, restamped, strayA, strayB],
      claims,
      fieldOnlyDumps,
    ).who.mac).toBe(CLIENT_MAC)
    const sameLine = `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`
    const talking = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: DISTRACTOR }
    expect(identityDonatesToVictim(
      talking,
      live,
      [identityOf('ip', LAN)!, talking, dcScoped!],
      sameLine,
    )).toBe(true)
    const dcFirst = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: DISTRACTOR }
    const restampedFromDc = { ...dcFirst, evidence_id: LAN }
    const fromDcIdentities = [
      identityOf('ip', LAN)!,
      restampedFromDc,
      dcScoped!,
      victimHost,
      victimUser,
      victimName,
    ]
    expect(identityDonatesToVictim(restampedFromDc, live, fromDcIdentities, fieldOnlyDumps)).toBe(true)
    expect(identityDonatesToVictim(dcScoped!, live, fromDcIdentities, fieldOnlyDumps)).toBe(false)
    const fromDc = requireCaseReport(live, fromDcIdentities, claims, fieldOnlyDumps, {
      who: omittedMac,
      where: omittedMac,
    })
    expect(fromDc.who).toEqual(projected)
    expect(fromDc.where).toEqual(projected)
    expect(fromDc.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(fromDc.where.mac).not.toBe(DISTRACTOR_MAC)
    expect(fromDc.who).toMatchObject({
      ip: LAN, hostname: HOST, user: USER, full_name: FULL_NAME,
    })
  })

  it('persists a submitted user when the projected victim row has no donated user', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const clientMac = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: LAN }
    const dcMac = { ...identityOf('mac', DISTRACTOR_MAC)!, evidence_id: DISTRACTOR }
    const victimHost = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const victimName = identityOf('full_name', FULL_NAME)!
    const identities = [identityOf('ip', LAN)!, clientMac, dcMac, victimHost, victimName]
    const frames = [
      `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`,
      `eth.src: ${DISTRACTOR_MAC}\tip.src: ${DISTRACTOR}`,
    ].join('\n')
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const submitted = {
      entity_id: LAN,
      ip: LAN,
      mac: DISTRACTOR_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    const projected = {
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    expect(projectVictimSlot(live, identities, frames)).toEqual({
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      full_name: FULL_NAME,
    })
    const report = requireCaseReport(live, identities, claims, frames, {
      who: submitted,
      where: JSON.stringify(submitted),
    })
    expect(report.who).toEqual(projected)
    expect(report.where).toEqual(projected)
    expect(report.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(report.where.mac).not.toBe(DISTRACTOR_MAC)
    const dcUser = { ...identityOf('user', DISTRACTOR_USER)!, evidence_id: DISTRACTOR }
    const dcHost = { ...identityOf('hostname', DISTRACTOR_HOST)!, evidence_id: DISTRACTOR }
    const foreign = requireCaseReport(
      live,
      [...identities, dcUser, dcHost],
      claims,
      frames,
      { who: { ...submitted, user: DISTRACTOR_USER, hostname: DISTRACTOR_HOST } },
    )
    expect(foreign.who.user).toBeUndefined()
    expect(foreign.who.hostname).toBe(HOST)
    expect(foreign.who).toMatchObject({
      ip: LAN, mac: CLIENT_MAC, hostname: HOST, full_name: FULL_NAME,
    })
    const noHost = requireCaseReport(
      live,
      [identityOf('ip', LAN)!, clientMac, dcHost, victimName],
      claims,
      frames,
      { who: { entity_id: LAN, ip: LAN, hostname: DISTRACTOR_HOST } },
    )
    expect(noHost.who.hostname).toBeUndefined()
    const omittedUser = {
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      full_name: FULL_NAME,
    }
    const omitted = requireCaseReport(live, identities, claims, frames, { who: omittedUser })
    expect(omitted.who.user).toBeUndefined()
    expect(omitted.who).toEqual({
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      full_name: FULL_NAME,
    })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, {
      user: USER,
      hostname: HOST,
      full_name: FULL_NAME,
      mac: DISTRACTOR_MAC,
      ip: '203.0.113.1',
    })).toEqual({
      entity_id: LAN,
      ip: LAN,
      user: USER,
      hostname: HOST,
      full_name: FULL_NAME,
    })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, { user: 'kerberos.CNameString' }))
      .toEqual({ entity_id: LAN, ip: LAN })
    expect(completeAcceptedSlot(
      { entity_id: LAN, ip: LAN },
      { user: USER },
      { relationship, endpoints: [] },
    )).toEqual({ entity_id: LAN, ip: LAN, user: USER })
    const victimUser = identityOf('user', USER)!
    expect(completeAcceptedSlot(
      { entity_id: LAN, ip: LAN },
      { user: USER },
      live,
      [identityOf('ip', LAN)!, victimUser],
      frames,
    )).toEqual({ entity_id: LAN, ip: LAN, user: USER })
  })

  it('persists a submitted victim MAC when the ledger first donated that MAC to the DC', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const dcDonated = {
      ...identityOf('mac', CLIENT_MAC)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const dcMac = { ...identityOf('mac', DISTRACTOR_MAC)!, evidence_id: DISTRACTOR }
    const victimHost = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const victimName = identityOf('full_name', FULL_NAME)!
    const identities = [identityOf('ip', LAN)!, dcDonated, dcMac, victimHost, victimName]
    const frames = [
      `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`,
      `eth.src: ${DISTRACTOR_MAC}\tip.src: ${DISTRACTOR}`,
    ].join('\n')
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const submitted = {
      entity_id: LAN,
      ip: '203.0.113.1',
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    expect(projectVictimSlot(live, identities, frames)).toEqual({
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      full_name: FULL_NAME,
    })
    expect(identityDonatesToVictim(dcDonated, live, identities, frames)).toBe(false)
    const projected = {
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    const report = requireCaseReport(live, identities, claims, frames, {
      who: submitted,
      where: JSON.stringify(submitted),
    })
    expect(report.who).toEqual(projected)
    expect(report.where).toEqual(projected)
    expect(report.who.ip).toBe(LAN)
    expect(report.who.ip).not.toBe('203.0.113.1')
    const distractorClose = requireCaseReport(live, identities, claims, frames, {
      who: { ...submitted, mac: DISTRACTOR_MAC },
    })
    expect(distractorClose.who.mac).toBeUndefined()
    expect(distractorClose.who).toEqual({
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    })
    const omittedMac = {
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    const omitted = requireCaseReport(live, identities, claims, frames, { who: omittedMac })
    expect(omitted.who).toEqual({ ...omittedMac, mac: CLIENT_MAC })
    expect(omitted.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(completeAcceptedSlot({ entity_id: LAN }, {
      mac: CLIENT_MAC,
      ip: '203.0.113.1',
      user: USER,
      hostname: HOST,
      full_name: FULL_NAME,
    }, live, identities, frames)).toEqual({
      entity_id: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, {
      mac: CLIENT_MAC,
      ip: '203.0.113.1',
      user: USER,
      hostname: HOST,
      full_name: FULL_NAME,
    }, live, identities, frames)).toEqual(projected)
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, {
      mac: DISTRACTOR_MAC,
    }, live, identities, frames)).toEqual({ entity_id: LAN, ip: LAN })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, {
      mac: CLIENT_MAC,
    })).toEqual({ entity_id: LAN, ip: LAN })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, {
      mac: CLIENT_MAC,
    }, { relationship, endpoints: [] }, identities, frames)).toEqual({ entity_id: LAN, ip: LAN })
    expect(completeAcceptedSlot({ entity_id: LAN, ip: LAN }, {
      mac: 'not-a-mac',
    }, live, identities, frames)).toEqual({ entity_id: LAN, ip: LAN })
    const dumpOnly = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: LAN, entity_id: DISTRACTOR }
    expect(completeAcceptedSlot(
      { entity_id: LAN, ip: LAN },
      { mac: CLIENT_MAC },
      live,
      [identityOf('ip', LAN)!, dumpOnly],
      `eth.src: ${CLIENT_MAC}`,
    )).toEqual({ entity_id: LAN, ip: LAN, mac: CLIENT_MAC })
    expect(completeAcceptedSlot(
      { entity_id: LAN, ip: LAN },
      { mac: CLIENT_MAC },
      live,
      [identityOf('ip', LAN)!],
      frames,
    )).toEqual({ entity_id: LAN, ip: LAN, mac: CLIENT_MAC })
  })

  it('persists a DC-stamped MAC unless talking-IP frames prove it DC-only', () => {
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const dcDonated = {
      ...identityOf('mac', CLIENT_MAC)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const dcMac = { ...identityOf('mac', DISTRACTOR_MAC)!, evidence_id: DISTRACTOR }
    const victimHost = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const victimUser = identityOf('user', USER)!
    const victimName = identityOf('full_name', FULL_NAME)!
    const identities = [identityOf('ip', LAN)!, dcDonated, dcMac, victimHost, victimUser, victimName]
    const dcTalking = `eth.src: ${DISTRACTOR_MAC}\tip.src: ${DISTRACTOR}`
    const conversations = `${LAN} → ${DISTRACTOR}  kerberos.CNameString: ${USER}`
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    const omitted = {
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    const projected = { ...omitted, mac: CLIENT_MAC }
    expect(projectVictimSlot(live, identities, dcTalking)).toEqual({
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    })
    expect(identityDonatesToVictim(dcDonated, live, identities, dcTalking)).toBe(false)
    const submitted = requireCaseReport(live, identities, claims, dcTalking, {
      who: omitted,
      where: { ...omitted, mac: CLIENT_MAC },
    })
    expect(submitted.who).toEqual(projected)
    expect(submitted.where).toEqual(projected)
    expect(submitted.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(submitted.where.mac).not.toBe(DISTRACTOR_MAC)
    const dcSubmitted = requireCaseReport(live, identities, claims, dcTalking, {
      who: { ...omitted, mac: DISTRACTOR_MAC },
      where: { ...omitted, mac: DISTRACTOR_MAC },
    })
    expect(dcSubmitted.who).toEqual(omitted)
    expect(dcSubmitted.where).toEqual(omitted)
    expect(dcSubmitted.who.mac).toBeUndefined()
    expect(dcSubmitted.where.mac).toBeUndefined()
    const filled = requireCaseReport(live, identities, claims, dcTalking, {
      who: omitted,
      where: omitted,
    })
    expect(filled.who).toEqual(projected)
    expect(filled.where).toEqual(projected)
    for (const evidence of [conversations, '']) {
      const withoutVictimLine = requireCaseReport(live, identities, claims, evidence, {
        who: omitted,
        where: { ...omitted, mac: CLIENT_MAC },
      })
      expect(withoutVictimLine.where).toEqual(projected)
      expect(withoutVictimLine.who).toEqual(omitted)
      expect(withoutVictimLine.who.mac).toBeUndefined()
      expect(withoutVictimLine.where.mac).toBe(CLIENT_MAC)
    }
  })

  it('persists omitted mac and user from victim-IP evidence after a live bind', () => {
    expect(resolveBind({
      relationship,
      endpoints: [{ addr: C2, role: 'victim', because: conversationBecause }],
    })).toEqual({ ok: false, reason: cueVictimUnboundReason(C2) })
    const live = bind({
      endpoints: [
        { addr: LAN, role: 'victim', because: conversationBecause },
        { addr: C2, role: 'c2', because: 'cue/observation address' },
        { addr: DISTRACTOR, role: 'distractor', because: 'idle or DC' },
      ],
    })
    const dcDonated = {
      ...identityOf('mac', CLIENT_MAC)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const dcMac = { ...identityOf('mac', DISTRACTOR_MAC)!, evidence_id: DISTRACTOR }
    const victimHost = { ...identityOf('hostname', HOST)!, evidence_id: LAN }
    const victimName = identityOf('full_name', FULL_NAME)!
    const victimUser = {
      ...identityOf('user', USER)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const distractorUser = {
      ...identityOf('user', DISTRACTOR_USER)!,
      evidence_id: DISTRACTOR,
      entity_id: DISTRACTOR,
    }
    const identities = [
      identityOf('ip', LAN)!, dcDonated, dcMac, victimHost, victimName, victimUser, distractorUser,
    ]
    const frames = [
      `eth.src: ${CLIENT_MAC}\tip.src: ${LAN}`,
      `eth.src: ${DISTRACTOR_MAC}\tip.src: ${DISTRACTOR}`,
    ].join('\n')
    const conversations = [
      `${LAN} → ${DISTRACTOR}  kerberos.CNameString: ${USER}`,
      `ip.src: ${DISTRACTOR}\tkerberos.CNameString: ${DISTRACTOR_USER}`,
    ].join('\n')
    const evidence = `${frames}\n${conversations}`
    const claims = { what: 'a', when: 'b', why: 'c', how: 'd' }
    expect(projectVictimSlot(live, identities, evidence)).toEqual({
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      full_name: FULL_NAME,
    })
    expect(identityDonatesToVictim(dcDonated, live, identities, evidence)).toBe(false)
    expect(identityDonatesToVictim(victimUser, live, identities, evidence)).toBe(false)
    expect(identityDonatesToVictim(distractorUser, live, identities, evidence)).toBe(false)
    const entityOnly = { entity_id: LAN }
    const projected = {
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    }
    const report = requireCaseReport(live, identities, claims, evidence, {
      who: entityOnly,
      where: JSON.stringify(entityOnly),
    })
    expect(report.who).toEqual(projected)
    expect(report.where).toEqual(projected)
    expect(report.who.mac).not.toBe(DISTRACTOR_MAC)
    expect(report.where.mac).not.toBe(DISTRACTOR_MAC)
    expect(report.who.user).not.toBe(DISTRACTOR_USER)
    expect(report.where.user).not.toBe(DISTRACTOR_USER)
    expect(report.who).toMatchObject({
      ip: LAN, hostname: HOST, full_name: FULL_NAME,
    })
    const noFrames = requireCaseReport(live, identities, claims, conversations, { who: entityOnly })
    expect(noFrames.who.mac).toBeUndefined()
    expect(noFrames.who.user).toBe(USER)
    expect(noFrames.who).toEqual({
      entity_id: LAN,
      ip: LAN,
      hostname: HOST,
      user: USER,
      full_name: FULL_NAME,
    })
    const noConversation = requireCaseReport(live, identities, claims, frames, { who: entityOnly })
    expect(noConversation.who.mac).toBe(CLIENT_MAC)
    expect(noConversation.who.user).toBeUndefined()
    expect(noConversation.who.user).not.toBe(DISTRACTOR_USER)
    const stamped = { ...identityOf('user', USER)!, evidence_id: LAN, entity_id: DISTRACTOR }
    const stampedLedger = [
      identityOf('ip', LAN)!, dcDonated, dcMac, victimHost, victimName, stamped, distractorUser,
    ]
    expect(identityDonatesToVictim(stamped, live, stampedLedger, frames)).toBe(false)
    const stampedClose = requireCaseReport(live, stampedLedger, claims, frames, { who: entityOnly })
    expect(stampedClose.who.user).toBe(USER)
    expect(stampedClose.who.user).not.toBe(DISTRACTOR_USER)
    expect(stampedClose.who).toMatchObject({
      ip: LAN, mac: CLIENT_MAC, hostname: HOST, full_name: FULL_NAME,
    })
    const dumpOnly = { ...identityOf('mac', CLIENT_MAC)!, evidence_id: LAN, entity_id: DISTRACTOR }
    expect(completeAcceptedSlot(
      { entity_id: LAN, ip: LAN, hostname: HOST, full_name: FULL_NAME },
      entityOnly,
      live,
      [identityOf('ip', LAN)!, dumpOnly, distractorUser],
      `eth.src: ${CLIENT_MAC}`,
    )).toEqual({
      entity_id: LAN,
      ip: LAN,
      mac: CLIENT_MAC,
      hostname: HOST,
      full_name: FULL_NAME,
    })
    expect(completeAcceptedSlot(
      { entity_id: LAN, ip: LAN },
      { mac: CLIENT_MAC, user: USER },
      live,
      identities,
      evidence,
    )).toEqual({ entity_id: LAN, ip: LAN, mac: CLIENT_MAC })
    expect(completeAcceptedSlot(
      { entity_id: LAN, ip: LAN },
      { mac: DISTRACTOR_MAC, user: DISTRACTOR_USER },
      live,
      identities,
      evidence,
    )).toEqual({ entity_id: LAN, ip: LAN })
  })
})
