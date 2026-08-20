import { describe, expect, it } from 'vitest'
import { INVALID_TSHARK_FIELDS, RECOMMENDED_TSHARK_FIELDS, rejectInvalidTsharkFields } from '../src/fields.ts'

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
})
