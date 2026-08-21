import { describe, expect, it } from 'vitest'
import type { SessionEvent } from '@deepseek-ai/dsh-session'
import {
  actionForHunt, applyHuntExtras, c2HypothesisId, chassisMission, CHASSIS_MISSION_PURPOSE,
  CUE_INVALID_REASON, CUE_PENDING_REASON, foldActions, foldExtras, foldMission, foldPlan,
  defaultOpenAlternative, hasAlternativeHypothesis, hypothesisIdForHunt,
  isBelieveBecauseClaim, killedHypothesisIds, namedLiveCue, planEntryDenyReason,
  planReady, planReadyDenyReason, PLAN_ALTERNATIVE_REASON, PLAN_C2_HYPOTHESIS_REASON,
  PLAN_INVENTORY_REASON, projectHuntExtras, requireC2HypothesisId, sameHuntExtras,
  thesisForHuntDump, completeDenyReason, completeUnboundWorkstationReason,
  COMPLETE_CUE_PENDING_REASON, COMPLETE_PLAN_NOT_READY_REASON,
  COMPLETE_UNBOUND_WORKSTATION_PREFIX,
} from '../src/mindset.ts'
import type {
  CaseReport, Hunt, Identity, InvestigationAction, InvestigationMission, InvestigationPlanEntry,
  RelationshipBind,
} from '../src/types.ts'

const LAN = '10.0.10.2'
const LAN2 = '10.0.10.8'
const DC = '10.0.10.3'
const HOST2 = 'lan-host-b'
const AD_SRV = '_ldap._tcp.default-first-site-name._sites.dc._msdcs.ad.example.lan'
const C2 = '198.51.100.80'
const EXTRA = '203.0.113.50'
const PAYLOAD = 'payload.example.test'

function event<T extends SessionEvent['type']>(type: T, data: SessionEvent['data']): SessionEvent {
  return { type, seq: 0, time: 0, data } as SessionEvent
}

const mission = (over: Partial<InvestigationMission> = {}): InvestigationMission => ({
  purpose: 'Scope an identity+C2 case',
  slots: { '0a': { value: 'valid' } },
  closedMeans: ['identity+c2'],
  cue: { addr: C2, evidence_id: 'conv-1' },
  cueValidation: 'valid',
  ...over,
})

const readyPlan = {
  inventory: ['evidence/a.pcap'],
  gaps: ['C2 domain unknown'],
  hypotheses: [
    {
      id: 'h-c2',
      claim: `I believe ${C2} is C2 because ${LAN} talks to that non-LAN cue`,
      disconfirm: 'SNI is a CDN or update name',
      label: 'c2' as const,
    },
    {
      id: 'h-cdn',
      claim: 'I believe 203.0.113.80 is CDN because update.microsoft.com is evidenced there',
      disconfirm: 'a non-CDN dotted name is evidenced on that IP',
      label: 'cdn' as const,
    },
  ],
}

const bind = (): RelationshipBind => ({
  relationship: {
    src: LAN, dst: C2, dport: 443, t: '2026-08-21T00:00:00Z', evidence_id: 'conv-1',
  },
  endpoints: [
    { addr: LAN, role: 'victim', because: `${LAN} talking to ${C2}` },
    { addr: C2, role: 'c2', because: 'cue' },
  ],
})

const report = (over: Partial<CaseReport> = {}): CaseReport => ({
  who: { entity_id: LAN, ip: LAN },
  what: 'beacon', when: 'now',
  where: { entity_id: LAN, ip: LAN },
  why: 'c2', how: 'https',
  ...over,
})

describe('analyst mindset chassis', () => {
  it('folds Mission, append-only Plan, Actions, and leftover extras', () => {
    expect(foldMission([])).toBeUndefined()
    expect(foldMission([
      event('investigation/mission', mission({ purpose: 'first' })),
      event('investigation/mission', mission({ purpose: 'second' })),
    ])?.purpose).toBe('second')
    const first: InvestigationPlanEntry = {
      inventory: ['evidence/a.pcap'],
      gaps: ['C2 domain unknown'],
      hypotheses: readyPlan.hypotheses,
    }
    const second: InvestigationPlanEntry = {
      inventory: ['evidence/a.pcap', 'notes/a.md'],
      gaps: ['C2 domain unknown', 'MAC unknown'],
      hypotheses: [
        { ...readyPlan.hypotheses[0]!, disconfirm: 'replaced' },
        {
          id: 'h-dc',
          claim: 'I believe 10.0.10.3 is a DC because it answers Kerberos',
          disconfirm: 'it talks only to the cue',
          label: 'dc',
        },
      ],
    }
    const plan = foldPlan([
      event('investigation/plan', first),
      event('investigation/plan', second),
    ])
    expect(plan.inventory).toEqual(['evidence/a.pcap', 'notes/a.md'])
    expect(plan.gaps).toEqual(['C2 domain unknown', 'MAC unknown'])
    expect(plan.hypotheses.map(item => item.id)).toEqual(['h-c2', 'h-cdn', 'h-dc'])
    expect(plan.hypotheses[0]?.disconfirm).toBe('SNI is a CDN or update name')
    expect(foldPlan([])).toEqual({ inventory: [], gaps: [], hypotheses: [] })
    expect(foldPlan([event('investigation/plan', { inventory: ['evidence/a.pcap'] })])).toEqual({
      inventory: ['evidence/a.pcap'],
      gaps: [],
      hypotheses: [],
    })
    expect(foldExtras([
      event('investigation/extras', { c2_ips: [C2] }),
      event('investigation/extras', { killed: ['h-cdn'] }),
    ])).toEqual({ c2_ips: [C2], killed: ['h-cdn'] })
    expect(foldExtras([
      event('investigation/extras', { c2_ips: [C2], killed: ['h-cdn'] }),
      event('investigation/report', report()),
    ])).toEqual({ c2_ips: [C2], killed: ['h-cdn'] })
    const action: InvestigationAction = {
      huntKind: 'extra-wan',
      subject: LAN,
      hypothesis_id: 'h-c2',
      thesis: thesisForHuntDump('extra-wan', true, false),
    }
    expect(foldActions([event('investigation/action', action)])).toEqual([action])
    expect(foldExtras([])).toBeUndefined()
    expect(foldExtras([event('investigation/extras', {})])).toBeUndefined()
    expect(foldExtras([
      event('investigation/extras', { c2_ips: [C2], c2_domain: PAYLOAD }),
      event('investigation/report', report({ c2_ips: [C2, EXTRA] })),
    ])).toEqual({ c2_ips: [C2, EXTRA], c2_domain: PAYLOAD })
    expect(applyHuntExtras(report(), undefined)).toEqual(report())
    expect(applyHuntExtras(report(), { c2_domain: PAYLOAD })).toEqual(report({ c2_domain: PAYLOAD }))
    expect(applyHuntExtras(report({ c2_ips: [C2] }), { c2_ips: [EXTRA], c2_domain: PAYLOAD })).toEqual(
      report({ c2_ips: [C2, EXTRA], c2_domain: PAYLOAD }),
    )
  })

  it('projects leftover extras without inventing who/where', () => {
    const identities: Identity[] = [
      { kind: 'ip', value: EXTRA, label: 'IP', evidence_id: LAN },
      { kind: 'ip', value: '203.0.113.60', label: 'IP', evidence_id: LAN },
      { kind: 'hostname', value: PAYLOAD, label: 'hostname', evidence_id: EXTRA },
      { kind: 'hostname', value: 'update.microsoft.com', label: 'hostname', evidence_id: '203.0.113.80' },
      { kind: 'ip', value: '203.0.113.80', label: 'IP', evidence_id: LAN },
    ]
    expect(projectHuntExtras(bind(), identities)).toEqual({
      c2_ips: [C2, EXTRA, '203.0.113.60'],
      c2_domain: PAYLOAD,
    })
    expect(projectHuntExtras(bind(), identities)?.c2_ips).not.toContain('203.0.113.80')
    expect(projectHuntExtras(bind(), [], '', ['h-cdn'])).toEqual({
      c2_ips: [C2],
      killed: ['h-cdn'],
    })
    expect(projectHuntExtras(bind(), [], '', [])).toEqual({ c2_ips: [C2] })
    expect(sameHuntExtras(undefined, { c2_ips: [C2] })).toBe(false)
    expect(sameHuntExtras({ c2_ips: [C2], c2_domain: PAYLOAD }, { c2_ips: [C2], c2_domain: PAYLOAD }))
      .toBe(true)
    expect(sameHuntExtras({ c2_ips: [C2] }, { c2_ips: [C2, EXTRA] })).toBe(false)
  })

  it('requires a ready Plan and does not treat Mission as enough', () => {
    expect(chassisMission().purpose).toBe(CHASSIS_MISSION_PURPOSE)
    expect(planReady(undefined, readyPlan)).toBe(false)
    expect(planReadyDenyReason(undefined, readyPlan)).toBe(CUE_PENDING_REASON)
    expect(planReady(chassisMission(), readyPlan)).toBe(false)
    expect(planReadyDenyReason(chassisMission(), readyPlan)).toBe(CUE_PENDING_REASON)
    expect(planReady(mission({ cueValidation: 'invalid' }), readyPlan)).toBe(false)
    expect(planReadyDenyReason(mission({ cueValidation: 'invalid' }), readyPlan)).toBe(CUE_INVALID_REASON)
    expect(planReady(mission(), { inventory: [], gaps: [], hypotheses: readyPlan.hypotheses }))
      .toBe(false)
    expect(planReadyDenyReason(mission(), { inventory: [], gaps: [], hypotheses: readyPlan.hypotheses }))
      .toBe(PLAN_INVENTORY_REASON)
    expect(planReady(mission(), { ...readyPlan, hypotheses: [readyPlan.hypotheses[0]!] })).toBe(false)
    expect(planReadyDenyReason(mission(), { ...readyPlan, hypotheses: [readyPlan.hypotheses[0]!] }))
      .toBe(PLAN_ALTERNATIVE_REASON)
    expect(planReady(mission(), {
      ...readyPlan,
      hypotheses: [{ ...readyPlan.hypotheses[0]!, label: 'victim' }, readyPlan.hypotheses[1]!],
    })).toBe(false)
    expect(planReadyDenyReason(mission(), {
      ...readyPlan,
      hypotheses: [{ ...readyPlan.hypotheses[0]!, label: 'victim' }, readyPlan.hypotheses[1]!],
    })).toBe(PLAN_C2_HYPOTHESIS_REASON)
    expect(namedLiveCue(undefined)).toBe(false)
    expect(namedLiveCue(chassisMission())).toBe(false)
    expect(namedLiveCue(mission({ cueValidation: 'invalid' }))).toBe(false)
    expect(namedLiveCue(mission({ cueValidation: 'open' }))).toBe(true)
    expect(namedLiveCue(mission())).toBe(true)
    expect(hasAlternativeHypothesis(readyPlan.hypotheses)).toBe(true)
    expect(hasAlternativeHypothesis([readyPlan.hypotheses[0]!])).toBe(false)
    expect(hasAlternativeHypothesis([defaultOpenAlternative()])).toBe(true)
    expect(isBelieveBecauseClaim(defaultOpenAlternative().claim)).toBe(true)
    expect(defaultOpenAlternative()).toEqual({
      id: 'h-alt',
      claim:
        'I believe a CDN or update alternative is still open because a well-known CDN or update dest has not been ruled out',
      disconfirm: 'a non-CDN dotted name is evidenced on that dest',
      label: 'cdn',
    })
    expect(planReady(mission({ cueValidation: 'open' }), readyPlan)).toBe(true)
    expect(planReady(mission(), readyPlan)).toBe(true)
    expect(planReadyDenyReason(undefined, { inventory: [], gaps: [], hypotheses: [] }))
      .toBe(CUE_PENDING_REASON)
    expect(planReadyDenyReason(mission(), readyPlan)).toBeUndefined()
    expect(completeDenyReason(undefined, readyPlan)).toBe(COMPLETE_CUE_PENDING_REASON)
    expect(completeDenyReason(chassisMission(), readyPlan)).toBe(COMPLETE_CUE_PENDING_REASON)
    expect(completeDenyReason(chassisMission(), { inventory: [], gaps: [], hypotheses: [] }))
      .toBe(COMPLETE_CUE_PENDING_REASON)
    expect(completeDenyReason(mission(), { inventory: [], gaps: [], hypotheses: [] }))
      .toBe(COMPLETE_PLAN_NOT_READY_REASON)
    expect(completeDenyReason(mission({ cueValidation: 'invalid' }), readyPlan))
      .toBe(COMPLETE_PLAN_NOT_READY_REASON)
    expect(completeDenyReason(mission({ cueValidation: 'open' }), readyPlan)).toBeUndefined()
    expect(completeDenyReason(mission(), readyPlan)).toBeUndefined()
    const leftoverIds: Identity[] = [
      { kind: 'ip', value: LAN, label: 'IP' },
      { kind: 'ip', value: LAN2, label: 'IP' },
      { kind: 'hostname', value: HOST2, label: 'hostname', evidence_id: LAN2 },
      { kind: 'ip', value: DC, label: 'IP' },
      { kind: 'hostname', value: AD_SRV, label: 'hostname', evidence_id: DC },
    ]
    const leftoverLedger = { binds: [bind()], identities: leftoverIds }
    const leftoverReason = completeUnboundWorkstationReason([{ ip: LAN2, hostname: HOST2 }])
    expect(leftoverReason).toContain(COMPLETE_UNBOUND_WORKSTATION_PREFIX)
    expect(leftoverReason).toContain(`${LAN2} (${HOST2})`)
    expect(leftoverReason).toContain('unbound')
    expect(completeDenyReason(mission(), readyPlan, leftoverLedger)).toBe(leftoverReason)
    expect(completeUnboundWorkstationReason([
      { ip: LAN2, hostname: HOST2 },
      { ip: '10.0.10.9', hostname: 'lan-host-c' },
    ])).toContain('workstations')
    expect(completeDenyReason(chassisMission(), readyPlan, leftoverLedger))
      .toBe(COMPLETE_CUE_PENDING_REASON)
    expect(completeDenyReason(mission(), { inventory: [], gaps: [], hypotheses: [] }, leftoverLedger))
      .toBe(COMPLETE_PLAN_NOT_READY_REASON)
    expect(completeDenyReason(mission(), readyPlan, {
      binds: [bind(), bind({
        relationship: {
          src: LAN2, dst: C2, dport: 443, t: '2026-08-21T00:01:00Z', evidence_id: 'conv-2',
        },
        endpoints: [
          { addr: LAN2, role: 'victim', because: `${LAN2} talking to ${C2}` },
          { addr: C2, role: 'c2', because: 'cue' },
        ],
      })],
      identities: leftoverIds,
    })).toBeUndefined()
    expect(completeDenyReason(mission(), readyPlan, {
      binds: [bind()],
      identities: [
        { kind: 'ip', value: LAN, label: 'IP' },
        { kind: 'ip', value: DC, label: 'IP' },
        { kind: 'hostname', value: AD_SRV, label: 'hostname', evidence_id: DC },
      ],
    })).toBeUndefined()
    expect(c2HypothesisId({ inventory: [], gaps: [], hypotheses: [] })).toBeUndefined()
    expect(c2HypothesisId(readyPlan)).toBe('h-c2')
    expect(requireC2HypothesisId(readyPlan)).toBe('h-c2')
    expect(() => requireC2HypothesisId({ inventory: [], gaps: [], hypotheses: [] }))
      .toThrow('Action requires a named C2 hypothesis')
    const eth: Hunt = { kind: 'eth-src', subjectKind: 'ip', subject: LAN }
    expect(hypothesisIdForHunt(eth, readyPlan)).toBe('h-c2')
    expect(hypothesisIdForHunt(eth, {
      ...readyPlan,
      hypotheses: [{
        id: 'h-victim',
        claim: 'I believe 10.0.10.2 is victim because it talks from that LAN IP',
        disconfirm: 'the MAC is a DC',
        label: 'victim',
      }, ...readyPlan.hypotheses],
    })).toBe('h-victim')
    expect(hypothesisIdForHunt(
      { kind: 'extra-wan', subjectKind: 'ip', subject: LAN },
      readyPlan,
    )).toBe('h-c2')
  })

  it('validates Plan claims and builds Action thesis rows', () => {
    expect(isBelieveBecauseClaim('I believe X because Y')).toBe(true)
    expect(isBelieveBecauseClaim('198.51.100.80 is C2')).toBe(false)
    expect(planEntryDenyReason({})).toBe('investigation_plan requires inventory, gaps, or a hypothesis')
    expect(planEntryDenyReason({
      hypotheses: [{ id: '  ', claim: 'I believe X because Y', disconfirm: 'kill', label: 'c2' }],
    })).toBe('investigation_plan hypothesis id must be a non-empty string')
    expect(planEntryDenyReason({
      hypotheses: [{ id: 'h', claim: 'nope', disconfirm: 'kill', label: 'c2' }],
    })).toContain('I believe X because Y')
    expect(planEntryDenyReason({
      hypotheses: [{ id: 'h', claim: 'I believe X because Y', disconfirm: '  ', label: 'c2' }],
    })).toBe('investigation_plan hypothesis disconfirm must be a non-empty string')
    expect(planEntryDenyReason({ inventory: ['evidence/a.pcap'] })).toBeUndefined()
    const hunt: Hunt = { kind: 'extra-wan', subjectKind: 'ip', subject: LAN }
    expect(actionForHunt(hunt, 'h-c2', thesisForHuntDump('extra-wan', false, false))).toEqual({
      huntKind: 'extra-wan',
      subject: LAN,
      hypothesis_id: 'h-c2',
      thesis: thesisForHuntDump('extra-wan', false, false),
    })
    expect(actionForHunt(hunt, 'h-c2', thesisForHuntDump('extra-wan', true, false), LAN).evidence_id)
      .toBe(LAN)
    expect(thesisForHuntDump('c2-domain', false, true).result).toBe('kill')
    expect(thesisForHuntDump('c2-domain', true, true).result).toBe('confirm')
    expect(thesisForHuntDump('eth-src', true, false).result).toBe('confirm')
    expect(thesisForHuntDump('eth-src', false, false).result).toBe('gap')
    expect(killedHypothesisIds([
      actionForHunt(hunt, 'h-c2', thesisForHuntDump('extra-wan', false, true)),
      actionForHunt(hunt, 'h-c2', thesisForHuntDump('extra-wan', false, true)),
      actionForHunt(hunt, 'h-cdn', thesisForHuntDump('c2-domain', true, false)),
    ])).toEqual(['h-c2'])
  })
})
