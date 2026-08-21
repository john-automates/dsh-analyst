import { describe, expect, it } from 'vitest'
import type { SessionEvent } from '@deepseek-ai/dsh-session'
import {
  c2TalkingLanIps, displayFilterFor, evidenceTextForHunts, foldToolResultText,
  c2DomainDisplayFilter, c2DomainHunt, extraWanDisplayFilter, extraWanHunt, huntFilterSpec,
  huntKey, huntNotice, huntsForNewIdentities, huntsToAutoRun, isLanIpv4, isNonLanUnicastIpv4,
  otherEndDisplayFilter, otherEndHunt, shouldAutoRunHunt,
} from '../src/hunts.ts'
import { formatLedger } from '../src/ledger.ts'
import type { Hunt, Identity } from '../src/types.ts'

const ip: Identity = { kind: 'ip', value: '10.0.0.5', label: 'IP' }
const host: Identity = { kind: 'hostname', value: 'workstation1', label: 'hostname' }
const user: Identity = { kind: 'user', value: 'brolf', label: 'user' }

const LAN_A = '10.0.10.2'
const LAN_B = '10.0.10.3'
const LAN_GW = '10.0.10.1'
const C2 = '198.51.100.80'

const twoClientFixture = [
  `${LAN_A} → ${C2} TCP`,
  `${LAN_B} → ${LAN_GW} NBNS`,
].join('\n')

const lanA: Identity = { kind: 'ip', value: LAN_A, label: 'IP' }
const lanB: Identity = { kind: 'ip', value: LAN_B, label: 'IP' }
const c2Peer: Identity = { kind: 'ip', value: C2, label: 'IP' }
const idleHost: Identity = { kind: 'hostname', value: 'lan-b-host', label: 'hostname' }
const idleUser: Identity = { kind: 'user', value: 'idleuser', label: 'user' }

function toolResultEvent(text: string, extra?: { empty?: boolean; otherBlock?: boolean }): SessionEvent {
  const content = extra?.empty === true
    ? []
    : extra?.otherBlock === true
      ? [{ type: 'text', text }]
      : [{
        type: 'tool-result',
        toolCallId: 'call-1',
        content: [
          { type: 'text', text },
          { type: 'image', url: 'about:blank' },
        ],
      }]
  return {
    type: 'tool/result',
    seq: 0,
    time: 0,
    data: { turn: 1, step: 1, message: { content } },
  } as SessionEvent
}

describe('auto-issued hunts', () => {
  it('issues MAC, name-service, Kerberos, and SAMR after a new IP', () => {
    expect(huntsForNewIdentities([ip], [])).toEqual([
      { kind: 'eth-src', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'name-service', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'kerberos-cname', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'samr-userinfo', subjectKind: 'ip', subject: '10.0.0.5' },
    ])
    expect(huntsForNewIdentities([host], [])).toEqual([
      { kind: 'kerberos-cname', subjectKind: 'hostname', subject: 'workstation1' },
      { kind: 'samr-userinfo', subjectKind: 'hostname', subject: 'workstation1' },
    ])
    expect(huntsForNewIdentities([user], [])).toEqual([
      { kind: 'samr-userinfo', subjectKind: 'user', subject: 'brolf' },
    ])
  })

  it('dedupes MAC, name-service, Kerberos, and SAMR against existing hunts and itself', () => {
    const first = huntsForNewIdentities([ip, host, user], [])
    expect(first).toEqual([
      { kind: 'eth-src', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'name-service', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'kerberos-cname', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'samr-userinfo', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'kerberos-cname', subjectKind: 'hostname', subject: 'workstation1' },
      { kind: 'samr-userinfo', subjectKind: 'hostname', subject: 'workstation1' },
      { kind: 'samr-userinfo', subjectKind: 'user', subject: 'brolf' },
    ])
    expect(huntsForNewIdentities([ip, host, user], first)).toEqual([])
    const kerberosOnly: Hunt = { kind: 'kerberos-cname', subjectKind: 'ip', subject: '10.0.0.5' }
    expect(huntsForNewIdentities([ip], [kerberosOnly])).toEqual([
      { kind: 'eth-src', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'name-service', subjectKind: 'ip', subject: '10.0.0.5' },
      { kind: 'samr-userinfo', subjectKind: 'ip', subject: '10.0.0.5' },
    ])
    expect(huntKey(kerberosOnly)).toContain('kerberos-cname')
  })

  it('scopes eth-src, CNameString, and SAMR to the C2-talking LAN IP on a two-client fixture', () => {
    expect(c2TalkingLanIps(twoClientFixture)).toEqual([LAN_A])
    expect(c2TalkingLanIps(`${LAN_A} -> ${C2}`)).toEqual([LAN_A])
    expect(c2TalkingLanIps(`ip.src: ${LAN_A}\tip.dst: ${C2}`)).toEqual([LAN_A])
    expect(c2TalkingLanIps(`${LAN_B} → ${LAN_GW}`)).toEqual([])
    expect(c2TalkingLanIps(`${LAN_A} → 224.0.0.252`)).toEqual([])
    expect(c2TalkingLanIps(`${LAN_A} → 255.255.255.255`)).toEqual([])
    expect(c2TalkingLanIps(`${LAN_A} → 0.0.0.0`)).toEqual([])
    expect(c2TalkingLanIps(`${LAN_A} → 127.0.0.1`)).toEqual([])
    expect(c2TalkingLanIps(`${LAN_A} → 169.254.1.1`)).toEqual([])
    expect(c2TalkingLanIps('no addresses here')).toEqual([])
    expect(c2TalkingLanIps(`172.16.1.2 → ${C2}`)).toEqual(['172.16.1.2'])
    expect(c2TalkingLanIps(`192.168.9.9 → ${C2}`)).toEqual(['192.168.9.9'])
    expect(c2TalkingLanIps(`172.15.1.2 → ${C2}`)).toEqual([])
    expect(c2TalkingLanIps(`172.32.1.2 → ${C2}`)).toEqual([])
    expect(c2TalkingLanIps(`${LAN_A} → ${C2}\n${LAN_A} → ${C2}`)).toEqual([LAN_A])
    expect(isLanIpv4(LAN_A)).toBe(true)
    expect(isLanIpv4(C2)).toBe(false)
    expect(isNonLanUnicastIpv4(C2)).toBe(true)
    expect(isNonLanUnicastIpv4(LAN_A)).toBe(false)

    const issued = huntsForNewIdentities([lanA, lanB, c2Peer, idleHost, idleUser], [], twoClientFixture)
    expect(issued).toEqual([
      { kind: 'eth-src', subjectKind: 'ip', subject: LAN_A },
      { kind: 'name-service', subjectKind: 'ip', subject: LAN_A },
      { kind: 'kerberos-cname', subjectKind: 'ip', subject: LAN_A },
      { kind: 'samr-userinfo', subjectKind: 'ip', subject: LAN_A },
    ])
    expect(issued.some(hunt => hunt.subject === LAN_B)).toBe(false)
    expect(issued.some(hunt => hunt.subject === C2)).toBe(false)
    expect(issued.some(hunt => hunt.subject === 'lan-b-host')).toBe(false)
    expect(issued.some(hunt => hunt.subject === 'idleuser')).toBe(false)
    expect(huntsForNewIdentities([idleHost, idleUser], issued, twoClientFixture)).toEqual([])

    for (const hunt of issued) {
      const notice = huntNotice(hunt)
      if (hunt.kind === 'eth-src') {
        expect(notice).toContain(`ip.src == ${LAN_A}`)
        expect(notice).toContain('eth.src')
        expect(notice).not.toContain('ip.addr ==')
      } else {
        expect(notice).toContain(`ip.addr == ${LAN_A}`)
      }
      expect(notice).not.toContain(`ip.addr == ${LAN_B}`)
      expect(notice).not.toContain(`ip.src == ${LAN_B}`)
    }
  })

  it('folds prior tool-result text into C2-talking evidence', () => {
    const prior = toolResultEvent(twoClientFixture)
    const empty = toolResultEvent('', { empty: true })
    const other = toolResultEvent('ignored', { otherBlock: true })
    const unrelated = { type: 'investigation/identity', seq: 1, time: 0, data: lanA } as SessionEvent
    expect(foldToolResultText([unrelated, empty, other, prior])).toBe(twoClientFixture)
    expect(foldToolResultText([])).toBe('')
    expect(evidenceTextForHunts([], twoClientFixture)).toBe(twoClientFixture)
    expect(evidenceTextForHunts([prior], '')).toBe(twoClientFixture)
    expect(evidenceTextForHunts([prior], 'later')).toBe(`${twoClientFixture}\nlater`)
    expect(huntsForNewIdentities([lanB, idleHost], [], evidenceTextForHunts([prior], ''))).toEqual([])
  })

  it('names valid tshark fields in hunt notices and formats the ledger', () => {
    const mac: Hunt = { kind: 'eth-src', subjectKind: 'ip', subject: '10.0.0.5' }
    const names: Hunt = { kind: 'name-service', subjectKind: 'ip', subject: '10.0.0.5' }
    const kerberos: Hunt = { kind: 'kerberos-cname', subjectKind: 'hostname', subject: 'workstation1' }
    const samr: Hunt = { kind: 'samr-userinfo', subjectKind: 'user', subject: 'brolf' }
    const macNotice = huntNotice(mac)
    expect(macNotice).toContain('eth.src')
    expect(macNotice).toContain('eth-src')
    expect(macNotice).toContain('ip.src == 10.0.0.5')
    expect(macNotice).not.toContain('ip.addr ==')
    const nameNotice = huntNotice(names)
    expect(nameNotice).toContain('llmnr')
    expect(nameNotice).toContain('nbns')
    expect(nameNotice).toContain('browser')
    expect(nameNotice).toContain('DESKTOP-*')
    expect(nameNotice).toContain('NBNS Registration')
    expect(nameNotice).toContain('BROWSER Host Announcement')
    expect(nameNotice).toContain('ip.addr == 10.0.0.5')
    expect(nameNotice).not.toContain('smb')
    const kerberosNotice = huntNotice(kerberos)
    expect(kerberosNotice).toContain('kerberos.CNameString')
    expect(kerberosNotice).toContain('ldap.sAMAccountName')
    expect(kerberosNotice).toContain('kerberos.username')
    expect(kerberosNotice).toContain('ldap.displayName')
    expect(kerberosNotice).toContain('samr.samr_UserInfo21.account_name')
    expect(kerberosNotice).toContain('samr.samr_UserInfo21.full_name')
    expect(kerberosNotice).not.toContain('ip.addr ==')
    expect(kerberosNotice).not.toContain('After a username appears')
    expect(huntNotice(samr)).toContain('samr.samr_UserInfo21.full_name')
    expect(huntNotice(samr)).toContain('Becka Rolf')
    expect(huntNotice(samr)).not.toContain('ip.addr ==')
    expect(() => huntNotice({ ...mac, kind: 'unknown' as Hunt['kind'] })).toThrow('huntNotice')
    expect(() => huntFilterSpec({ ...mac, kind: 'unknown' as Hunt['kind'] })).toThrow('huntFilterSpec')
    expect(displayFilterFor('eth.src', mac)).toBe('(eth.src) and ip.src == 10.0.0.5')
    expect(displayFilterFor('kerberos.CNameString', kerberos)).toBe('kerberos.CNameString')
    expect(huntFilterSpec(mac)).toEqual({
      display_filter: '(eth.src) and ip.src == 10.0.0.5',
      fields: ['eth.src'],
    })
    expect(huntFilterSpec(names)).toEqual({
      display_filter: '(llmnr or nbns or browser) and ip.addr == 10.0.0.5',
      fields: [],
    })
    expect(huntFilterSpec(kerberos)).toEqual({
      display_filter: 'kerberos.CNameString',
      fields: ['kerberos.CNameString'],
    })
    expect(huntFilterSpec(samr)).toEqual({
      display_filter: 'samr.samr_UserInfo21.account_name or samr.samr_UserInfo21.full_name',
      fields: ['samr.samr_UserInfo21.account_name', 'samr.samr_UserInfo21.full_name'],
    })
    expect(formatLedger([], [], undefined)).toBe('')
    expect(formatLedger([], [], undefined, undefined, '', {
      purpose: 'This is a victim-identity + C2 investigation.',
      slots: { '0a': { value: 'valid' } },
      closedMeans: ['who/where proven on the victim'],
      cue: { addr: C2, evidence_id: 'conv-1' },
      cueValidation: 'valid',
    })).toContain('Mission: This is a victim-identity + C2 investigation.')
    expect(formatLedger([], [], undefined, undefined, '', undefined, {
      inventory: ['evidence/a.pcap'],
      gaps: [],
      hypotheses: [{
        id: 'h-c2',
        claim: 'I believe 198.51.100.80 is C2 because 10.0.10.2 talks to that cue',
        disconfirm: 'SNI is a CDN or update name',
        label: 'c2',
      }],
    })).toContain('Plan: 1 hypotheses')
    expect(formatLedger([ip], [kerberos], { who: 'x' })).toContain('Identities:')
    expect(formatLedger([ip], [kerberos], { who: 'x' })).toContain('Hunts:')
    expect(formatLedger([ip], [kerberos], { who: 'x' })).toContain('case_report')
    expect(formatLedger([], [kerberos], undefined)).toContain('Hunts:')
    expect(formatLedger([], [], { who: 'x' })).toContain('case_report')
  })

  it('auto-runs LAN-subject hunts and skips a non-LAN C2 IP', () => {
    const lanMac: Hunt = { kind: 'eth-src', subjectKind: 'ip', subject: LAN_A }
    const idleMac: Hunt = { kind: 'eth-src', subjectKind: 'ip', subject: LAN_B }
    const c2Mac: Hunt = { kind: 'eth-src', subjectKind: 'ip', subject: C2 }
    const loopback: Hunt = { kind: 'eth-src', subjectKind: 'ip', subject: '127.0.0.1' }
    const hostHunt: Hunt = { kind: 'kerberos-cname', subjectKind: 'hostname', subject: 'workstation1' }
    const userHunt: Hunt = { kind: 'samr-userinfo', subjectKind: 'user', subject: 'brolf' }
    expect(shouldAutoRunHunt(lanMac, '')).toBe(true)
    expect(shouldAutoRunHunt(c2Mac, '')).toBe(false)
    expect(shouldAutoRunHunt(loopback, '')).toBe(false)
    expect(shouldAutoRunHunt(hostHunt, '')).toBe(true)
    expect(shouldAutoRunHunt(userHunt, '')).toBe(true)
    expect(shouldAutoRunHunt(lanMac, twoClientFixture)).toBe(true)
    expect(shouldAutoRunHunt(idleMac, twoClientFixture)).toBe(false)
    expect(shouldAutoRunHunt(c2Mac, twoClientFixture)).toBe(false)
    expect(shouldAutoRunHunt(hostHunt, twoClientFixture)).toBe(false)
    expect(shouldAutoRunHunt(userHunt, twoClientFixture)).toBe(false)
    const issued = [c2Mac, idleMac, lanMac, hostHunt]
    expect(huntsToAutoRun(issued, twoClientFixture, new Set())).toEqual([lanMac])
    expect(huntsToAutoRun(issued, '', new Set())).toEqual([idleMac, lanMac, hostHunt])
    expect(huntsToAutoRun(issued, twoClientFixture, new Set([huntKey(lanMac)]))).toEqual([])
  })

  it('issues other-end for a cue IP and auto-runs that hunt', () => {
    const hunt = otherEndHunt(C2)
    expect(hunt).toEqual({ kind: 'other-end', subjectKind: 'ip', subject: C2 })
    expect(otherEndDisplayFilter(C2)).toBe(`ip.dst == ${C2}`)
    expect(huntFilterSpec(hunt)).toEqual({
      display_filter: `ip.dst == ${C2}`,
      fields: ['ip.src'],
    })
    const notice = huntNotice(hunt)
    expect(notice).toContain('other-end')
    expect(notice).toContain(`ip.dst == ${C2}`)
    expect(notice).toContain('ip.src')
    expect(notice).not.toContain(LAN_A)
    expect(shouldAutoRunHunt(hunt, '')).toBe(true)
    expect(shouldAutoRunHunt(hunt, twoClientFixture)).toBe(true)
    expect(shouldAutoRunHunt({ kind: 'other-end', subjectKind: 'ip', subject: LAN_A }, '')).toBe(false)
    expect(huntsToAutoRun([hunt], twoClientFixture, new Set())).toEqual([hunt])
    expect(huntsForNewIdentities([c2Peer], [])).not.toContainEqual(hunt)
  })

  it('issues c2-domain for a bound C2 IP and auto-runs that hunt', () => {
    const hunt = c2DomainHunt(C2)
    expect(hunt).toEqual({ kind: 'c2-domain', subjectKind: 'ip', subject: C2 })
    expect(c2DomainDisplayFilter(C2)).toBe(
      `(tls.handshake.extensions_server_name or dns.qry.name or dns.resp.name) and ip.addr == ${C2}`,
    )
    expect(huntFilterSpec(hunt)).toEqual({
      display_filter: c2DomainDisplayFilter(C2),
      fields: [
        'tls.handshake.extensions_server_name',
        'dns.qry.name',
        'dns.resp.name',
      ],
    })
    const notice = huntNotice(hunt)
    expect(notice).toContain('c2-domain')
    expect(notice).toContain(`ip.addr == ${C2}`)
    expect(notice).toContain('tls.handshake.extensions_server_name')
    expect(notice).toContain('dns.qry.name')
    expect(notice).toContain('dns.resp.name')
    expect(notice).not.toContain(LAN_A)
    expect(shouldAutoRunHunt(hunt, '')).toBe(true)
    expect(shouldAutoRunHunt(hunt, twoClientFixture)).toBe(true)
    expect(shouldAutoRunHunt({ kind: 'c2-domain', subjectKind: 'ip', subject: LAN_A }, '')).toBe(false)
    expect(huntsToAutoRun([hunt], twoClientFixture, new Set())).toEqual([])
    expect(huntsToAutoRun([hunt], twoClientFixture, new Set(), true)).toEqual([hunt])
    expect(huntsForNewIdentities([c2Peer], [])).not.toContainEqual(hunt)
  })

  it('issues extra-wan for a bound victim IP and auto-runs that hunt', () => {
    const hunt = extraWanHunt(LAN_A)
    expect(hunt).toEqual({ kind: 'extra-wan', subjectKind: 'ip', subject: LAN_A })
    expect(extraWanDisplayFilter(LAN_A, C2)).toContain(`ip.src == ${LAN_A}`)
    expect(extraWanDisplayFilter(LAN_A, C2)).toContain(`not ip.dst == ${C2}`)
    expect(extraWanDisplayFilter(LAN_A, C2)).toContain('10.0.0.0/8')
    expect(extraWanDisplayFilter(LAN_A, C2)).toContain('224.0.0.0/3')
    expect(huntFilterSpec(hunt, C2)).toEqual({
      display_filter: extraWanDisplayFilter(LAN_A, C2),
      fields: ['ip.dst'],
    })
    const notice = huntNotice(hunt)
    expect(notice).toContain('extra-wan')
    expect(notice).toContain(`ip.src == ${LAN_A}`)
    expect(notice).toContain('ip.dst')
    expect(notice).not.toContain(C2)
    expect(shouldAutoRunHunt(hunt, '')).toBe(true)
    expect(shouldAutoRunHunt(hunt, twoClientFixture)).toBe(true)
    expect(shouldAutoRunHunt({ kind: 'extra-wan', subjectKind: 'ip', subject: C2 }, '')).toBe(false)
    expect(shouldAutoRunHunt({ kind: 'extra-wan', subjectKind: 'ip', subject: LAN_B }, twoClientFixture))
      .toBe(true)
    expect(huntsToAutoRun([hunt], twoClientFixture, new Set())).toEqual([])
    expect(huntsToAutoRun([hunt], twoClientFixture, new Set(), true)).toEqual([hunt])
    expect(huntsForNewIdentities([lanA], [], twoClientFixture)).not.toContainEqual(hunt)
  })
})
