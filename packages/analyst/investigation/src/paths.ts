/**
 * Case-directory path containment and evidence classification.
 * @module @deepseek-ai/dsh-investigation/paths
 */

import { extname, isAbsolute, relative, resolve, sep } from 'node:path'

/** Capture and log suffixes treated as evidence even outside `evidence/`. */
const EVIDENCE_EXTENSIONS = new Set(['.pcap', '.pcapng', '.cap', '.log'])

/**
 * Case-root close files. After a live bind, write/edit of these paths is denied;
 * close is `case_report`. The set is closed; `report.md` is not parsed into who/where.
 */
export const CASE_ROOT_CLOSE_FILES = ['report.md', 'report.txt', 'case_report.md'] as const

const CASE_ROOT_CLOSE_FILE_SET = new Set<string>(CASE_ROOT_CLOSE_FILES)

/**
 * Whether a `path.relative` result escaped its root.
 * An absolute `rel` is the Windows different-drive case; POSIX escapes use `..`.
 * @param rel - result of `path.relative(root, resolved)`.
 * @returns true when `rel` is not a descendant (the root itself is `''`).
 */
export function relativeEscapesRoot(rel: string): boolean {
  return rel.startsWith('..') || isAbsolute(rel)
}

/**
 * Resolve `target` against `caseDir` and require the result to stay inside it.
 * @param caseDir - absolute case directory.
 * @param target - absolute or case-relative path.
 * @returns the resolved absolute path.
 */
export function resolveInsideCase(caseDir: string, target: string): string {
  const root = resolve(caseDir)
  const resolved = isAbsolute(target) ? resolve(target) : resolve(root, target)
  const rel = relative(root, resolved)
  if (relativeEscapesRoot(rel)) {
    throw new Error(`path ${target} is outside the case directory ${root}`)
  }
  return resolved
}

/**
 * Whether `target` resolves inside `caseDir` (the case root itself counts).
 * @param caseDir - absolute case directory.
 * @param target - absolute or case-relative path.
 * @returns true when the resolved path is the case root or a descendant.
 */
export function isInsideCase(caseDir: string, target: string): boolean {
  try {
    resolveInsideCase(caseDir, target)
    return true
  } catch {
    return false
  }
}

/**
 * Whether a resolved path is read-only evidence: under `evidence/`, or a
 * capture/log suffix at any depth inside the case.
 * @param caseDir - absolute case directory.
 * @param target - absolute or case-relative path.
 * @returns true when writes must be denied while evidence is read-only.
 */
export function isEvidencePath(caseDir: string, target: string): boolean {
  const resolved = resolveInsideCase(caseDir, target)
  const rel = relative(resolve(caseDir), resolved)
  if (rel === '') return false
  const parts = rel.split(sep)
  if (parts[0] === 'evidence') return true
  return EVIDENCE_EXTENSIONS.has(extname(resolved).toLowerCase())
}

/**
 * Whether a resolved path may be written while evidence stays read-only:
 * anything under `notes/`, or `report.md` at the case root.
 * @param caseDir - absolute case directory.
 * @param target - absolute or case-relative path.
 * @returns true when the path is a permitted write target.
 */
export function isWritablePath(caseDir: string, target: string): boolean {
  const resolved = resolveInsideCase(caseDir, target)
  const rel = relative(resolve(caseDir), resolved)
  if (rel === 'report.md') return true
  return rel === 'notes' || rel.startsWith(`notes${sep}`)
}

/**
 * Whether `target` is a case-root close file (`report.md` and similar names).
 * Nested paths such as `notes/report.md` are not close files.
 * @param caseDir - absolute case directory.
 * @param target - absolute or case-relative path.
 * @returns true when write/edit of this path is a close-file substitute.
 */
export function isCaseRootClosePath(caseDir: string, target: string): boolean {
  const resolved = resolveInsideCase(caseDir, target)
  const rel = relative(resolve(caseDir), resolved)
  if (rel === '' || rel.includes(sep)) return false
  return CASE_ROOT_CLOSE_FILE_SET.has(rel.toLowerCase())
}

/**
 * Whether a string looks like a filesystem path rather than a filter or field.
 * @param token - one command token or argument value.
 * @returns true when the token should be checked for case containment.
 */
export function looksLikePath(token: string): boolean {
  if (token === '' || token.startsWith('-')) return false
  if (token.startsWith('/') || token.startsWith('./') || token.startsWith('../')) return true
  if (token.includes('\\')) return true
  return token.includes('/') && /\.\w+$/.test(token)
}
