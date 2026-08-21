import { describe, expect, it } from 'vitest'
import {
  CLOSE_FILE_REASON, denyCommand, denyReason, firstDefined, stringArg, tokenizeCommand,
} from '../src/policy.ts'

const CASE = '/cases/alpha'

describe('investigation policy', () => {
  it('tokenizes quoted commands and reads string arguments', () => {
    expect(tokenizeCommand('tshark -r "my file.pcap" -Y \'kerberos.CNameString\'')).toEqual([
      'tshark', '-r', 'my file.pcap', '-Y', 'kerberos.CNameString',
    ])
    expect(stringArg({ file_path: '/a' }, ['file_path', 'path'])).toBe('/a')
    expect(stringArg({ path: '' }, ['path'])).toBeUndefined()
    expect(stringArg('nope', ['path'])).toBeUndefined()
    expect(stringArg({ other: 1 }, ['path'])).toBeUndefined()
  })

  it('denies writes to evidence and paths outside the case', () => {
    expect(denyReason(
      { name: 'write', arguments: { file_path: '/etc/passwd' } },
      CASE,
      true,
    )).toContain('outside the case directory')
    expect(denyReason(
      { name: 'edit', arguments: { file_path: `${CASE}/evidence/a.pcap` } },
      CASE,
      true,
    )).toContain('read-only')
    expect(denyReason(
      { name: 'write', arguments: { file_path: `${CASE}/notes/a.md` } },
      CASE,
      true,
    )).toBeUndefined()
    expect(denyReason(
      { name: 'write', arguments: { file_path: `${CASE}/report.md` } },
      CASE,
      true,
    )).toBe(CLOSE_FILE_REASON)
    expect(denyReason(
      { name: 'edit', arguments: { path: `${CASE}/report.md` } },
      CASE,
      true,
    )).toBe(CLOSE_FILE_REASON)
    expect(denyReason(
      { name: 'str_replace_editor', arguments: { file_path: `${CASE}/case_report.md` } },
      CASE,
      false,
    )).toBe(CLOSE_FILE_REASON)
    expect(denyReason(
      { name: 'write', arguments: { file_path: `${CASE}/report.txt` } },
      CASE,
      true,
    )).toBe(CLOSE_FILE_REASON)
    expect(denyReason(
      { name: 'write', arguments: { file_path: `${CASE}/notes/report.md` } },
      CASE,
      true,
    )).toBeUndefined()
    expect(denyReason(
      { name: 'write', arguments: { file_path: `${CASE}/evidence/a.pcap` } },
      CASE,
      false,
    )).toBeUndefined()
    expect(denyReason(
      { name: 'read', arguments: { file_path: `${CASE}/evidence/a.pcap` } },
      CASE,
      true,
    )).toBeUndefined()
  })

  it('denies malware runners, evidence execution, and outside-case shell operands', () => {
    expect(denyCommand('wine evidence/malware.exe', CASE, true)).toContain('execute or emulate')
    expect(denyCommand('wine64 evidence/malware.exe', CASE, true)).toContain('execute or emulate')
    expect(denyCommand('./evidence/dropper.exe', CASE, true)).toContain('captured binaries')
    expect(denyCommand('cat ../evidence/dropper.exe', CASE, true)).toContain('captured binaries')
    expect(denyCommand('chmod +x evidence/dropper.exe', CASE, true)).toContain('executable')
    expect(denyCommand('cat /etc/passwd', CASE, true)).toContain('outside the case directory')
    expect(denyCommand('tshark -r evidence/a.pcap -Y kerberos.CNameString', CASE, true)).toBeUndefined()
    expect(denyCommand('/usr/bin/tshark -r evidence/a.pcap', CASE, true)).toBeUndefined()
    expect(denyCommand('echo hello', CASE, true)).toBeUndefined()
    expect(denyReason(
      { name: 'bash', arguments: { command: 'cat /etc/passwd', workdir: '/tmp' } },
      CASE,
      true,
    )).toContain('working directory')
    expect(denyReason(
      { name: 'bash', arguments: { command: 'cat evidence/a.pcap > evidence/out.pcap' } },
      CASE,
      true,
    )).toContain('read-only')
    expect(denyReason({ name: 'bash', arguments: {} }, CASE, true)).toBeUndefined()
    expect(denyCommand('', CASE, true)).toBeUndefined()
    expect(denyCommand('tee evidence/out.pcap', CASE, true)).toContain('read-only')
    expect(denyCommand('cat a > /tmp/out', CASE, true)).toContain('outside')
    expect(denyCommand('echo hi > notes/ok.md', CASE, true)).toBeUndefined()
    expect(denyCommand('echo hi > captured.pcap', CASE, true)).toContain('read-only')
    expect(denyCommand('cat ../tmp/dropper.exe', CASE, true)).toContain('captured binaries')
    expect(denyCommand('C:\\\\Windows\\\\wine64 evidence/malware.exe', CASE, true)).toContain('execute or emulate')
    expect(denyCommand('env /usr/bin/tshark -r evidence/a.pcap', CASE, true)).toBeUndefined()
    expect(firstDefined(undefined, undefined)).toBeUndefined()
    expect(firstDefined(undefined, 'kept')).toBe('kept')
  })
})
