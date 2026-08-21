import { describe, expect, it } from 'vitest'
import { identityOf } from '../src/harvest.ts'
import { bindCaseReportToC2TalkingLan, c2TalkingLanVictim } from '../src/index.ts'
import type { CaseReport, Identity } from '../src/types.ts'

const LAN = '10.0.10.2'
const LAN_IDLE = '10.0.10.3'
const C2 = '198.51.100.80'
const CLIENT_MAC = '02:00:00:00:00:0a'
const C2_MAC = '02:00:00:00:00:cc'

const lan = identityOf('ip', LAN)!
const idle = identityOf('ip', LAN_IDLE)!
const c2 = identityOf('ip', C2)!
const clientMac = identityOf('mac', CLIENT_MAC)!
const remoteMac = identityOf('mac', C2_MAC)!
const host = identityOf('hostname', 'lan-host')!

const conversation = `${LAN} → ${C2} TCP`

function report(over: Partial<CaseReport> = {}): CaseReport {
  return {
    who: C2,
    what: `beacon to ${C2}`,
    when: '2026-08-21',
    where: `${C2} ${C2_MAC}`,
    why: 'c2',
    how: 'https',
    ...over,
  }
}

describe('case_report C2-talking LAN bind', () => {
  it('resolves a unique ledger LAN IP that shares the ledger with a non-LAN peer', () => {
    expect(c2TalkingLanVictim([lan, c2, clientMac])).toEqual({ ip: LAN, mac: CLIENT_MAC })
    expect(c2TalkingLanVictim([lan, c2])).toEqual({ ip: LAN })
    expect(c2TalkingLanVictim([lan, idle, c2])).toBeUndefined()
    expect(c2TalkingLanVictim([lan])).toBeUndefined()
    expect(c2TalkingLanVictim([c2, clientMac])).toBeUndefined()
    expect(c2TalkingLanVictim([lan, c2, identityOf('ip', '127.0.0.1')!])).toEqual({ ip: LAN })
    expect(c2TalkingLanVictim([])).toBeUndefined()
  })

  it('prefers c2TalkingLanIps over an idle LAN on the ledger', () => {
    expect(c2TalkingLanVictim([idle, lan, c2], conversation)).toEqual({ ip: LAN })
    expect(c2TalkingLanVictim([], conversation)).toEqual({ ip: LAN })
    expect(c2TalkingLanVictim([lan, c2, clientMac, remoteMac], conversation)).toEqual({ ip: LAN })
  })

  it('rewrites who/where that name the C2 IP or a remote MAC to the LAN client', () => {
    const identities: Identity[] = [lan, c2, clientMac, host]
    const bound = bindCaseReportToC2TalkingLan(report(), identities)
    expect(bound.who).toBe(LAN)
    expect(bound.where).toBe(`${LAN} ${CLIENT_MAC}`)
    expect(bound.what).toBe(`beacon to ${C2}`)
    expect(bound.how).toBe('https')
    expect(bound.who).not.toContain('lan-host')
  })

  it('rewrites from evidence focus when the ledger has no identities', () => {
    const bound = bindCaseReportToC2TalkingLan(report({ where: C2 }), [], conversation)
    expect(bound.who).toBe(LAN)
    expect(bound.where).toBe(LAN)
  })

  it('does not invent a MAC or a hostname', () => {
    const bound = bindCaseReportToC2TalkingLan(report({ who: C2, where: C2 }), [lan, c2, host])
    expect(bound.who).toBe(LAN)
    expect(bound.where).toBe(LAN)
    expect(bound.who).not.toContain(CLIENT_MAC)
    expect(bound.who).not.toContain('lan-host')
  })

  it('leaves a field that already names the focus LAN IP or sourced MAC', () => {
    const identities: Identity[] = [lan, c2, clientMac]
    const already = report({
      who: `${LAN} talked to ${C2}`,
      where: `${CLIENT_MAC} on ${LAN}`,
    })
    expect(bindCaseReportToC2TalkingLan(already, identities)).toBe(already)
  })

  it('does not rewrite an idle LAN IP or replace a MAC when several MACs are on the ledger', () => {
    const idleWho = report({ who: LAN_IDLE, where: `${C2} ${C2_MAC}` })
    const twoMacs = bindCaseReportToC2TalkingLan(idleWho, [lan, idle, c2, clientMac, remoteMac], conversation)
    expect(twoMacs.who).toBe(LAN_IDLE)
    expect(twoMacs.where).toBe(`${LAN} ${C2_MAC}`)
  })

  it('replaces a dashed remote MAC and returns the original report when nothing matches', () => {
    const identities: Identity[] = [lan, c2, clientMac]
    const dashed = bindCaseReportToC2TalkingLan(report({ who: '02-00-00-00-00-CC', where: LAN }), identities)
    expect(dashed.who).toBe(CLIENT_MAC)
    expect(dashed.where).toBe(LAN)
    const untouched = report({ who: 'workstation', where: 'lab' })
    expect(bindCaseReportToC2TalkingLan(untouched, identities)).toBe(untouched)
    expect(bindCaseReportToC2TalkingLan(report(), [])).toEqual(report())
  })
})
