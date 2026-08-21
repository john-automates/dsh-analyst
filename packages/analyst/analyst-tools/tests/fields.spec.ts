import { describe, expect, it } from 'vitest'
import {
  coercePcapFilterFields,
  INVALID_TSHARK_FIELDS,
  RECOMMENDED_TSHARK_FIELDS,
  rejectInvalidTsharkFields,
  unwrapPcapDisplayFilter,
} from '../src/fields.ts'

describe('tshark field validation', () => {
  it('accepts recommended fields and rejects the invalid 4.4.16 names', () => {
    expect(rejectInvalidTsharkFields([...RECOMMENDED_TSHARK_FIELDS])).toEqual([...RECOMMENDED_TSHARK_FIELDS])
    expect(rejectInvalidTsharkFields([])).toEqual([])
    expect(() => rejectInvalidTsharkFields(['ldap.sAMAccountName'])).toThrow('ldap.sAMAccountName')
    expect(() => rejectInvalidTsharkFields(['ldap.displayName', 'kerberos.CNameString'])).toThrow('ldap.displayName')
    expect(() => rejectInvalidTsharkFields(['kerberos.username'])).toThrow('kerberos.username')
    expect(() => rejectInvalidTsharkFields(['SAMR.FULL_NAME'])).toThrow('samr.full_name')
    expect(INVALID_TSHARK_FIELDS).toContain('samr.full_name')
  })

  it('coerces a string fields value into names before invalid-field rejection', () => {
    expect(coercePcapFilterFields(undefined)).toEqual([])
    expect(coercePcapFilterFields('kerberos.CNameString')).toEqual(['kerberos.CNameString'])
    expect(coercePcapFilterFields('kerberos.CNameString, samr.samr_UserInfo21.account_name')).toEqual([
      'kerberos.CNameString',
      'samr.samr_UserInfo21.account_name',
    ])
    expect(coercePcapFilterFields('kerberos.CNameString samr.samr_UserInfo21.full_name')).toEqual([
      'kerberos.CNameString',
      'samr.samr_UserInfo21.full_name',
    ])
    expect(coercePcapFilterFields('  , kerberos.CNameString ,  ')).toEqual(['kerberos.CNameString'])
    expect(coercePcapFilterFields(['kerberos.CNameString'])).toEqual(['kerberos.CNameString'])
    expect(rejectInvalidTsharkFields(coercePcapFilterFields('kerberos.CNameString'))).toEqual([
      'kerberos.CNameString',
    ])
    expect(() => rejectInvalidTsharkFields(coercePcapFilterFields('ldap.sAMAccountName'))).toThrow(
      'ldap.sAMAccountName',
    )
    expect(() => rejectInvalidTsharkFields(coercePcapFilterFields('ldap.displayName kerberos.username'))).toThrow(
      'ldap.displayName',
    )
    expect(() => rejectInvalidTsharkFields(coercePcapFilterFields('samr.full_name'))).toThrow('samr.full_name')
  })

  it('strips wrapping quotes from display_filter and leaves inner quotes alone', () => {
    expect(unwrapPcapDisplayFilter(undefined)).toBeUndefined()
    expect(unwrapPcapDisplayFilter('')).toBeUndefined()
    expect(unwrapPcapDisplayFilter('   ')).toBeUndefined()
    expect(unwrapPcapDisplayFilter('""')).toBeUndefined()
    expect(unwrapPcapDisplayFilter('"ip.addr == 1.2.3.4"')).toBe('ip.addr == 1.2.3.4')
    expect(unwrapPcapDisplayFilter("'llmnr or nbns or browser'")).toBe('llmnr or nbns or browser')
    expect(unwrapPcapDisplayFilter('\\"ip.addr == 1.2.3.4\\"')).toBe('ip.addr == 1.2.3.4')
    expect(unwrapPcapDisplayFilter("'\\\"ip.addr == 1.2.3.4\\\"'")).toBe('ip.addr == 1.2.3.4')
    expect(unwrapPcapDisplayFilter('\'"ip.addr == 1.2.3.4"\'')).toBe('ip.addr == 1.2.3.4')
    expect(unwrapPcapDisplayFilter('""ip.addr == 1.2.3.4""')).toBe('ip.addr == 1.2.3.4')
    expect(unwrapPcapDisplayFilter('  "ip.addr == 1.2.3.4"  ')).toBe('ip.addr == 1.2.3.4')
    expect(unwrapPcapDisplayFilter('ip.addr == 1.2.3.4')).toBe('ip.addr == 1.2.3.4')
    expect(unwrapPcapDisplayFilter('http.host == "example.com"')).toBe('http.host == "example.com"')
    expect(unwrapPcapDisplayFilter('"smb" or nbns')).toBe('"smb" or nbns')
  })
})
