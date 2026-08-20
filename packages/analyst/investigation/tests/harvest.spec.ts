import { describe, expect, it } from 'vitest'
import {
  decodeUtf16LeHex, harvestIdentities, identityKey, identityOf, IDENTITY_LABELS, normalizeIdentityValue,
  regexCapture,
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
})
