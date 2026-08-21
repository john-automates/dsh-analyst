import { describe, expect, it } from 'vitest'
import {
  decodeUtf16LeHex, harvestIdentities, identityKey, identityOf, IDENTITY_LABELS, ipsEvidencingIdentity,
  normalizeIdentityValue, regexCapture,
} from '../src/harvest.ts'

const BECKA_HEX = '42:00:65:00:63:00:6b:00:61:00:20:00:52:00:6f:00:6c:00:66:00'

describe('identity harvest', () => {
  it('normalizes MAC, hostname, IP, and full-name whitespace', () => {
    expect(normalizeIdentityValue('mac', 'AA-BB-CC-DD-EE-FF')).toBe('aa:bb:cc:dd:ee:ff')
    expect(normalizeIdentityValue('hostname', 'WORKSTATION1')).toBe('workstation1')
    expect(normalizeIdentityValue('ip', '10.1.2.3')).toBe('10.1.2.3')
    expect(normalizeIdentityValue('user', ' brolf ')).toBe('brolf')
    expect(normalizeIdentityValue('full_name', '  Becka   Rolf ')).toBe('Becka Rolf')
    expect(normalizeIdentityValue('user', '   ')).toBeUndefined()
    expect(identityOf('user', '   ')).toBeUndefined()
    expect(IDENTITY_LABELS.full_name).toBe('full name')
  })

  it('decodes UTF-16LE SAMR hex to Becka Rolf and rejects non-text', () => {
    expect(decodeUtf16LeHex(BECKA_HEX)).toBe('Becka Rolf')
    expect(decodeUtf16LeHex(BECKA_HEX.replace(/:/g, ''))).toBe('Becka Rolf')
    expect(decodeUtf16LeHex(`\\x${BECKA_HEX}`)).toBe('Becka Rolf')
    expect(decodeUtf16LeHex(`0x${BECKA_HEX.replace(/:/g, '')}`)).toBe('Becka Rolf')
    expect(decodeUtf16LeHex('00')).toBeUndefined()
    expect(decodeUtf16LeHex('000102')).toBeUndefined()
    expect(decodeUtf16LeHex('00010203')).toBeUndefined()
    expect(decodeUtf16LeHex('42000000')).toBeUndefined()
  })

  it('harvests labeled identities and skips broadcast IPs', () => {
    const identities = harvestIdentities([
      'src 10.0.0.5 dst 0.0.0.0 also 255.255.255.255',
      'mac: AA:BB:CC:DD:EE:FF',
      'hostname: WORKSTATION1',
      'host: 10.1.2.3',
      'kerberos.CNameString: brolf',
      `samr.samr_UserInfo21.full_name: ${BECKA_HEX}`,
    ].join('\n'))
    expect(identities).toEqual([
      { kind: 'ip', value: '10.0.0.5', label: 'IP' },
      { kind: 'ip', value: '10.1.2.3', label: 'IP' },
      { kind: 'mac', value: 'aa:bb:cc:dd:ee:ff', label: 'MAC' },
      { kind: 'hostname', value: 'workstation1', label: 'hostname' },
      { kind: 'user', value: 'brolf', label: 'user' },
      { kind: 'full_name', value: 'Becka Rolf', label: 'full name' },
    ])
    const first = identities[0]
    if (first === undefined) throw new Error('expected a harvested IP')
    expect(identityKey(first)).toBe('ip\u000010.0.0.5')
  })

  it('dedupes repeated values and still decodes unlabeled SAMR hex', () => {
    const identities = harvestIdentities(`
      ip: 10.0.0.5
      10.0.0.5
      user: alice
      user: alice
      ${BECKA_HEX}
      full_name: Already Name
    `)
    expect(identities.filter(item => item.kind === 'ip')).toHaveLength(1)
    expect(identities.filter(item => item.kind === 'user')).toHaveLength(1)
    expect(identities.some(item => item.value === 'Becka Rolf')).toBe(true)
    expect(identities.some(item => item.value === 'Already Name')).toBe(true)
    expect(harvestIdentities('user:').filter(item => item.kind === 'user')).toEqual([])
    expect(harvestIdentities('00:01:02:03:04:05:06:07').some(item => item.kind === 'full_name')).toBe(false)
    expect(regexCapture(['all'] as unknown as RegExpMatchArray)).toBe('')
    expect(regexCapture(['all', 'kept'] as unknown as RegExpMatchArray)).toBe('kept')
  })

  it('harvests hostname from NBNS, BROWSER, SMB, and LLMNR summaries', () => {
    const identities = harvestIdentities([
      '    12 0.123456  10.2.28.88 → 224.0.0.252    LLMNR 82 Standard query ANY DESKTOP-TEYQ2NR',
      '    13 0.123457  10.2.28.88 → 10.2.28.255    NBNS 92 Registration NB DESKTOP-TEYQ2NR<00>',
      '    14 0.123458  10.2.28.88 → 10.2.28.255    NBNS 92 Registration NB DESKTOP-TEYQ2NR<20>',
      '    15 0.123459  10.2.28.88 → 10.2.28.255    BROWSER 243 Request Announcement DESKTOP-TEYQ2NR',
      '    16 0.123460  10.2.28.88 → 10.2.28.255    BROWSER 243 Host Announcement DESKTOP-TEYQ2NR, Workstation, Server',
      '    17 0.123461  10.2.28.88 → 10.2.28.88     SMB 128 Tree Connect AndX Request, Path: \\\\DESKTOP-TEYQ2NR\\IPC$',
      '    18 0.123462  10.2.28.88 → 10.2.28.255    NBNS 92 Registration NB EASYAS123<00>',
      '    19 0.123463  10.2.28.88 → 10.2.28.255    NBNS 92 Registration NB EASYAS123<1d>',
      '    20 0.123464  10.2.28.88 → 10.2.28.255    BROWSER 243 Request Announcement EASYAS123',
      '    21 0.123465  10.2.28.88 → 10.2.28.255    BROWSER 243 Domain/Workgroup Announcement EASYAS123, NT Workstation',
      '    22 0.123466  10.2.28.88 → 10.2.28.255    BROWSER 243 Local Master Announcement EASYAS123',
    ].join('\n'))
    expect(identities.filter(item => item.kind === 'hostname')).toEqual([
      { kind: 'hostname', value: 'desktop-teyq2nr', label: 'hostname' },
    ])
    expect(identities.some(item => item.value === 'easyas123')).toBe(false)
  })

  it('keeps IP, MAC, user, and full_name harvest beside summary hostnames', () => {
    const identities = harvestIdentities([
      '10.2.28.88',
      '00:19:d1:b2:4d:ad',
      'user: brolf',
      'full_name: Becka Rolf',
      'LLMNR Standard query ANY DESKTOP-TEYQ2NR',
      'NBNS Registration NB DESKTOP-TEYQ2NR<00>',
      'NBNS Registration NB DESKTOP-TEYQ2NR<20>',
      'BROWSER Request Announcement DESKTOP-TEYQ2NR',
      'BROWSER Host Announcement DESKTOP-TEYQ2NR',
      'BROWSER Domain/Workgroup Announcement EASYAS123',
    ].join('\n'))
    expect(identities).toEqual([
      { kind: 'ip', value: '10.2.28.88', label: 'IP' },
      { kind: 'mac', value: '00:19:d1:b2:4d:ad', label: 'MAC' },
      { kind: 'hostname', value: 'desktop-teyq2nr', label: 'hostname' },
      { kind: 'user', value: 'brolf', label: 'user' },
      { kind: 'full_name', value: 'Becka Rolf', label: 'full name' },
    ])
  })

  it('covers remaining summary hostname forms and skips workgroup NBNS suffixes', () => {
    const identities = harvestIdentities([
      'LLMNR Standard query response 0x0001 A WORKSTATION1',
      'LLMNR query 0xab AAAA WORKSTATION1',
      'NBNS Name query NB WORKSTATION1<03>',
      'SMB2 Tree Connect Request Tree: \\\\WORKSTATION1\\IPC$',
      'NBNS Registration NB EASYAS123<1b>',
      'NBNS Registration NB EASYAS123<1c>',
      'NBNS Registration NB EASYAS123<1e>',
    ].join('\n'))
    expect(identities.filter(item => item.kind === 'hostname')).toEqual([
      { kind: 'hostname', value: 'workstation1', label: 'hostname' },
    ])
  })

  it('records only the MAC sourced from the C2-talking LAN IP on a two-client fixture', () => {
    const LAN_A = '10.0.10.2'
    const LAN_B = '10.0.10.3'
    const LAN_GW = '10.0.10.1'
    const C2 = '198.51.100.80'
    const MAC_A = '02:00:00:00:00:0a'
    const MAC_B = '02:00:00:00:00:0b'
    const MAC_FAR = '02:00:00:00:00:cc'
    const evidence = `${LAN_A} → ${C2} TCP\n${LAN_B} → ${LAN_GW} NBNS`

    const bidirectional = harvestIdentities([
      `eth.src: ${MAC_A}\tip.src: ${LAN_A}\tip.dst: ${C2}`,
      `eth.src: ${MAC_FAR}\tip.src: ${C2}\tip.dst: ${LAN_A}`,
      `eth.src: ${MAC_B}\tip.src: ${LAN_B}\tip.dst: ${LAN_GW}`,
    ].join('\n'), evidence)
    expect(bidirectional.filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: MAC_A, label: 'MAC', evidence_id: LAN_A },
    ])

    const arrows = harvestIdentities([
      `${LAN_A} → ${C2}  ${MAC_A} → ${MAC_FAR} TCP`,
      `${C2} → ${LAN_A}  ${MAC_FAR} → ${MAC_A} TCP`,
      `${LAN_B} → ${LAN_GW}  ${MAC_B} → ${MAC_FAR} NBNS`,
    ].join('\n'))
    expect(arrows.filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: MAC_A, label: 'MAC', evidence_id: LAN_A },
    ])

    const arp = harvestIdentities([
      evidence,
      `ARP ${LAN_A} is at ${MAC_A}`,
      `ARP ${LAN_B} is at ${MAC_B}`,
    ].join('\n'))
    expect(arp.filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: MAC_A, label: 'MAC', evidence_id: LAN_A },
    ])

    const majority = harvestIdentities([
      `eth.src: ${MAC_A}`,
      `eth.src: ${MAC_A}`,
      `eth.src: ${MAC_FAR}`,
    ].join('\n'), evidence)
    expect(majority.filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: MAC_A, label: 'MAC' },
    ])

    const tie = harvestIdentities([
      `eth.src: ${MAC_A}`,
      `eth.src: ${MAC_FAR}`,
    ].join('\n'), evidence)
    expect(tie.filter(item => item.kind === 'mac')).toEqual([])

    const noMac = harvestIdentities(`ip.src: ${LAN_A}\tip.dst: ${C2}`, evidence)
    expect(noMac.filter(item => item.kind === 'mac')).toEqual([])

    const bogusSrc = harvestIdentities(
      `ip.src: 999.1.1.1\teth.src: ${MAC_FAR}\n${LAN_A} → ${C2}`,
      evidence,
    )
    expect(bogusSrc.filter(item => item.kind === 'mac')).toEqual([])

    const labeledOnArrow = harvestIdentities(
      `eth.src: ${MAC_A}\t${LAN_A} → ${C2}`,
    )
    expect(labeledOnArrow.filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: MAC_A, label: 'MAC', evidence_id: LAN_A },
    ])

    const srcWithoutEthLabel = harvestIdentities(`ip.src: ${LAN_A}\t${MAC_A}`, evidence)
    expect(srcWithoutEthLabel.filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: MAC_A, label: 'MAC', evidence_id: LAN_A },
    ])

    const fieldOnlyOne = harvestIdentities(`eth.src: ${MAC_A}`, evidence)
    expect(fieldOnlyOne.filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: MAC_A, label: 'MAC' },
    ])

    const emptyFieldDump = harvestIdentities('no addresses here', evidence)
    expect(emptyFieldDump.filter(item => item.kind === 'mac')).toEqual([])
  })

  it('stamps MAC evidence_id from the talking IP, not the hunt-subject scopeIp', () => {
    const LAN_A = '10.0.10.2'
    const LAN_B = '10.0.10.3'
    const MAC_A = '02:00:00:00:00:0a'
    const HOST_A = 'lan-host'
    const stamped = harvestIdentities(
      `eth.src: ${MAC_A}\thostname: ${HOST_A}\tip.src: ${LAN_A}`,
      `eth.src: ${MAC_A}\thostname: ${HOST_A}\tip.src: ${LAN_A}`,
      LAN_A,
    )
    expect(stamped.filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: MAC_A, label: 'MAC', evidence_id: LAN_A },
    ])
    expect(stamped.filter(item => item.kind === 'hostname')).toEqual([
      { kind: 'hostname', value: HOST_A, label: 'hostname', evidence_id: LAN_A },
    ])
    expect(stamped.find(item => item.kind === 'ip')?.evidence_id).toBeUndefined()
    const dcHunt = harvestIdentities(
      `eth.src: ${MAC_A}\thostname: ${HOST_A}\tip.src: ${LAN_A}`,
      `eth.src: ${MAC_A}\thostname: ${HOST_A}\tip.src: ${LAN_A}`,
      LAN_B,
    )
    expect(dcHunt.filter(item => item.kind === 'mac')).toEqual([
      { kind: 'mac', value: MAC_A, label: 'MAC', evidence_id: LAN_A },
    ])
    expect(dcHunt.filter(item => item.kind === 'hostname')).toEqual([
      { kind: 'hostname', value: HOST_A, label: 'hostname', evidence_id: LAN_B },
    ])
    expect(harvestIdentities(`${LAN_A} → 198.51.100.80  ${MAC_A}`, `${LAN_A} → 198.51.100.80  ${MAC_A}`, LAN_B)
      .find(item => item.kind === 'mac')).toEqual({ kind: 'mac', value: MAC_A, label: 'MAC', evidence_id: LAN_A })
    expect(harvestIdentities(`ARP ${LAN_A} is at ${MAC_A}`, `ARP ${LAN_A} is at ${MAC_A}`, LAN_B)
      .find(item => item.kind === 'mac')).toEqual({ kind: 'mac', value: MAC_A, label: 'MAC', evidence_id: LAN_A })
    expect(harvestIdentities(`eth.src: ${MAC_A}`, `eth.src: ${MAC_A}`, LAN_B).find(item => item.kind === 'mac'))
      .toEqual({ kind: 'mac', value: MAC_A, label: 'MAC' })
    expect(harvestIdentities(`eth.src: ${MAC_A}`, `eth.src: ${MAC_A}`, '  ').find(item => item.kind === 'mac'))
      .toEqual({ kind: 'mac', value: MAC_A, label: 'MAC' })
    const mac = identityOf('mac', MAC_A)!
    const host = identityOf('hostname', HOST_A)!
    expect(ipsEvidencingIdentity(mac, `eth.src: ${MAC_A}\tip.src: ${LAN_A}`)).toEqual([LAN_A])
    expect(ipsEvidencingIdentity(host, `hostname: ${HOST_A}\tip.addr: ${LAN_A}`)).toEqual([LAN_A])
    expect(ipsEvidencingIdentity(host, `NBNS Registration NB LAN-HOST<00>\tip.src: ${LAN_A}`)).toEqual([LAN_A])
    expect(ipsEvidencingIdentity(host, `(llmnr or nbns) and ip.addr == ${LAN_A}\thostname: ${HOST_A}`)).toEqual([LAN_A])
    expect(ipsEvidencingIdentity(mac, `eth.src: ${MAC_A}\tip.src: ${LAN_A}\neth.src: ${MAC_A}\tip.src: ${LAN_B}`))
      .toEqual([LAN_A, LAN_B])
    expect(ipsEvidencingIdentity(identityOf('user', 'lan-user')!, `user: lan-user\tip.addr: ${LAN_A}`)).toEqual([])
    expect(ipsEvidencingIdentity(host, `hostname: other-host\tip.addr: ${LAN_A}`)).toEqual([])
    expect(ipsEvidencingIdentity(mac, `eth.src: 02:00:00:00:00:0b\tip.src: ${LAN_A}`)).toEqual([])
    expect(ipsEvidencingIdentity(mac, `${LAN_A} → 198.51.100.80  ${MAC_A}`)).toEqual([LAN_A])
    expect(ipsEvidencingIdentity(mac, `ARP ${LAN_A} is at ${MAC_A}`)).toEqual([LAN_A])
    expect(ipsEvidencingIdentity(mac, `eth.src: ${MAC_A}\tip.src: 0.0.0.0`)).toEqual([])
    expect(ipsEvidencingIdentity(host, `hostname: ${HOST_A}`)).toEqual([])
    expect(ipsEvidencingIdentity(
      host,
      `hostname: ${HOST_A}\tip.addr: ${LAN_A}\nhostname: ${HOST_A}\tip.src: ${LAN_A}`,
    )).toEqual([LAN_A])
    expect(ipsEvidencingIdentity(host, `NBNS Registration NB otherhost<00>\tip.src: ${LAN_A}`)).toEqual([])
  })
})
