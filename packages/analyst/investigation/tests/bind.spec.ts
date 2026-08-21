import { describe, expect, it } from 'vitest'
import {
  caseReportDenyReason, cueVictimUnboundReason, defaultRoleForAddr, foldBind, formatRolesCard,
  identityDonatesToVictim, isCueObservationAddr, normalizeEndpointAddr, otherEndHuntForDeniedBind,
  projectCaseReport, projectVictimSlot, requireCaseReport, resolveBind, roleForIdentity,
  UNBOUND_REASON, VICTIM_COUNT_REASON,
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
})
