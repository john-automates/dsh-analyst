import { describe, expect, it } from 'vitest'
import { formatLedger, huntKey, huntNotice, huntsForNewIdentities } from '../src/hunts.ts'
import type { Hunt, Identity } from '../src/types.ts'

const ip: Identity = { kind: 'ip', value: '10.0.0.5', label: 'IP' }
const host: Identity = { kind: 'hostname', value: 'workstation1', label: 'hostname' }
const user: Identity = { kind: 'user', value: 'brolf', label: 'user' }

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

  it('names valid tshark fields in hunt notices and formats the ledger', () => {
    const mac: Hunt = { kind: 'eth-src', subjectKind: 'ip', subject: '10.0.0.5' }
    const names: Hunt = { kind: 'name-service', subjectKind: 'ip', subject: '10.0.0.5' }
    const kerberos: Hunt = { kind: 'kerberos-cname', subjectKind: 'hostname', subject: 'workstation1' }
    const samr: Hunt = { kind: 'samr-userinfo', subjectKind: 'user', subject: 'brolf' }
    const macNotice = huntNotice(mac)
    expect(macNotice).toContain('eth.src')
    expect(macNotice).toContain('eth-src')
    const nameNotice = huntNotice(names)
    expect(nameNotice).toContain('llmnr')
    expect(nameNotice).toContain('nbns')
    expect(nameNotice).toContain('browser')
    expect(nameNotice).toContain('DESKTOP-*')
    expect(nameNotice).toContain('NBNS Registration')
    expect(nameNotice).toContain('BROWSER Host Announcement')
    expect(nameNotice).not.toContain('smb')
    const kerberosNotice = huntNotice(kerberos)
    expect(kerberosNotice).toContain('kerberos.CNameString')
    expect(kerberosNotice).toContain('ldap.sAMAccountName')
    expect(kerberosNotice).toContain('kerberos.username')
    expect(kerberosNotice).toContain('ldap.displayName')
    expect(kerberosNotice).toContain('samr.samr_UserInfo21.account_name')
    expect(kerberosNotice).toContain('samr.samr_UserInfo21.full_name')
    expect(kerberosNotice).not.toContain('After a username appears')
    expect(huntNotice(samr)).toContain('samr.samr_UserInfo21.full_name')
    expect(huntNotice(samr)).toContain('Becka Rolf')
    expect(() => huntNotice({ ...mac, kind: 'unknown' as Hunt['kind'] })).toThrow('huntNotice')
    expect(formatLedger([], [], undefined)).toBe('')
    expect(formatLedger([ip], [kerberos], { who: 'x' })).toContain('Identities:')
    expect(formatLedger([ip], [kerberos], { who: 'x' })).toContain('Hunts:')
    expect(formatLedger([ip], [kerberos], { who: 'x' })).toContain('case_report')
    expect(formatLedger([], [kerberos], undefined)).toContain('Hunts:')
    expect(formatLedger([], [], { who: 'x' })).toContain('case_report')
  })
})
