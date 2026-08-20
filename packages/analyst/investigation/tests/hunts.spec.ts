import { describe, expect, it } from 'vitest'
import { formatLedger, huntKey, huntNotice, huntsForNewIdentities } from '../src/hunts.ts'
import type { Hunt, Identity } from '../src/types.ts'

const ip: Identity = { kind: 'ip', value: '10.0.0.5', label: 'IP' }
const host: Identity = { kind: 'hostname', value: 'workstation1', label: 'hostname' }
const user: Identity = { kind: 'user', value: 'brolf', label: 'user' }

describe('auto-issued hunts', () => {
  it('issues Kerberos after IP/hostname and SAMR after user, skipping duplicates', () => {
    const first = huntsForNewIdentities([ip, host, user], [])
    expect(first.map(hunt => hunt.kind)).toEqual(['kerberos-cname', 'kerberos-cname', 'samr-userinfo'])
    expect(first[0]).toEqual({ kind: 'kerberos-cname', subjectKind: 'ip', subject: '10.0.0.5' })
    expect(first[2]).toEqual({ kind: 'samr-userinfo', subjectKind: 'user', subject: 'brolf' })
    expect(huntsForNewIdentities([ip, user], first)).toEqual([])
    expect(huntKey(first[0]!)).toContain('kerberos-cname')
  })

  it('names valid tshark fields in hunt notices and formats the ledger', () => {
    const kerberos: Hunt = { kind: 'kerberos-cname', subjectKind: 'hostname', subject: 'workstation1' }
    const samr: Hunt = { kind: 'samr-userinfo', subjectKind: 'user', subject: 'brolf' }
    expect(huntNotice(kerberos)).toContain('kerberos.CNameString')
    expect(huntNotice(kerberos)).toContain('ldap.sAMAccountName')
    expect(huntNotice(samr)).toContain('samr.samr_UserInfo21.full_name')
    expect(huntNotice(samr)).toContain('Becka Rolf')
    expect(formatLedger([], [], undefined)).toBe('')
    expect(formatLedger([ip], [kerberos], { who: 'x' })).toContain('Identities:')
    expect(formatLedger([ip], [kerberos], { who: 'x' })).toContain('Hunts:')
    expect(formatLedger([ip], [kerberos], { who: 'x' })).toContain('case_report')
    expect(formatLedger([], [kerberos], undefined)).toContain('Hunts:')
    expect(formatLedger([], [], { who: 'x' })).toContain('case_report')
  })
})
