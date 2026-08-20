import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  isEvidencePath, isInsideCase, isWritablePath, looksLikePath, relativeEscapesRoot, resolveInsideCase,
} from '../src/paths.ts'

const CASE = '/cases/alpha'

describe('case path containment', () => {
  it('resolves relative and absolute descendants and rejects escapes', () => {
    expect(resolveInsideCase(CASE, 'evidence/a.pcap')).toBe(join(CASE, 'evidence/a.pcap'))
    expect(resolveInsideCase(CASE, join(CASE, 'notes/a.md'))).toBe(join(CASE, 'notes/a.md'))
    expect(resolveInsideCase(CASE, CASE)).toBe(CASE)
    expect(() => resolveInsideCase(CASE, '../outside')).toThrow('outside the case directory')
    expect(() => resolveInsideCase(CASE, '/etc/passwd')).toThrow('outside the case directory')
    expect(isInsideCase(CASE, 'notes/a.md')).toBe(true)
    expect(isInsideCase(CASE, '/etc/passwd')).toBe(false)
  })

  it('classifies evidence, writable notes, and path-like tokens', () => {
    expect(isEvidencePath(CASE, 'evidence/a.bin')).toBe(true)
    expect(isEvidencePath(CASE, 'capture.pcap')).toBe(true)
    expect(isEvidencePath(CASE, 'dir/trace.pcapng')).toBe(true)
    expect(isEvidencePath(CASE, 'auth.log')).toBe(true)
    expect(isEvidencePath(CASE, 'notes/a.md')).toBe(false)
    expect(isEvidencePath(CASE, CASE)).toBe(false)
    expect(isWritablePath(CASE, 'notes/a.md')).toBe(true)
    expect(isWritablePath(CASE, 'notes')).toBe(true)
    expect(isWritablePath(CASE, 'report.md')).toBe(true)
    expect(isWritablePath(CASE, 'evidence/a.pcap')).toBe(false)
    expect(looksLikePath('/tmp/a')).toBe(true)
    expect(looksLikePath('./a')).toBe(true)
    expect(looksLikePath('../a')).toBe(true)
    expect(looksLikePath('C:\\windows\\a')).toBe(true)
    expect(looksLikePath('dir/file.pcap')).toBe(true)
    expect(looksLikePath('kerberos.CNameString')).toBe(false)
    expect(looksLikePath('-Y')).toBe(false)
    expect(looksLikePath('')).toBe(false)
  })

  it('treats an absolute relative() result as an escape (Windows different-drive)', () => {
    expect(relativeEscapesRoot('')).toBe(false)
    expect(relativeEscapesRoot('notes/a.md')).toBe(false)
    expect(relativeEscapesRoot('../outside')).toBe(true)
    expect(relativeEscapesRoot('/etc/passwd')).toBe(true)
  })
})
