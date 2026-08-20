/**
 * Case-scoped tool-call policy: evidence stays read-only, work stays inside
 * the case directory, and captured binaries are not executed.
 * @module @deepseek-ai/dsh-investigation/policy
 */

import { isEvidencePath, isInsideCase, isWritablePath, looksLikePath, resolveInsideCase } from './paths.ts'

/** Tools that write a `file_path` or `path` argument. */
const WRITE_TOOLS = new Set(['write', 'edit', 'str_replace_editor'])

/** Tools whose primary operand is a filesystem path. */
const PATH_TOOLS = new Set([
  'write', 'edit', 'str_replace_editor', 'read', 'grep', 'glob',
  'pcap_info', 'pcap_filter', 'logs',
])

/** Shell tools whose `command` is inspected. */
const SHELL_TOOLS = new Set(['bash', 'pwsh'])

/** Executables that run captured binaries or emulators. */
const MALWARE_RUNNERS = /^(?:wine|wine64|qemu|qemu-system-\S+|vboxmanage)$/i

/** Evidence suffixes that must not be executed. */
const EXECUTABLE_EVIDENCE = /\.(?:exe|dll|bin|scr|msi|bat|cmd|ps1|vbs)$/i

/**
 * Split a shell command into quoted and unquoted tokens.
 * @param command - raw bash or pwsh command text.
 * @returns tokens with quotes stripped.
 */
export function tokenizeCommand(command: string): string[] {
  const tokens: string[] = []
  const matcher = /"([^"]*)"|'([^']*)'|(\S+)/g
  let match = matcher.exec(command)
  while (match !== null) {
    tokens.push(firstDefined(match[1], match[2], match[3]) as string)
    match = matcher.exec(command)
  }
  return tokens
}

/**
 * Read a string field from tool arguments when present.
 * @param args - parsed tool arguments.
 * @param keys - candidate field names.
 * @returns the first string value, or undefined.
 */
export function stringArg(args: unknown, keys: readonly string[]): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined
  const record = args as Record<string, unknown>
  for (const key of keys) {
    const value = record[key]
    if (typeof value === 'string' && value !== '') return value
  }
  return undefined
}

/**
 * Why one tool call must be denied, or undefined to allow it.
 * @param exec - tool name and parsed arguments.
 * @param caseDir - absolute case directory.
 * @param evidenceReadOnly - when true, evidence and capture files cannot be written.
 * @returns a model-facing deny reason, or undefined.
 */
export function denyReason(
  exec: { name: string; arguments: unknown },
  caseDir: string,
  evidenceReadOnly: boolean,
): string | undefined {
  const pathValue = stringArg(exec.arguments, ['file_path', 'path', 'file'])
  if (pathValue !== undefined && PATH_TOOLS.has(exec.name)) {
    if (!isInsideCase(caseDir, pathValue)) {
      return `refusing ${exec.name}: ${pathValue} is outside the case directory ${caseDir}`
    }
    if (WRITE_TOOLS.has(exec.name) && evidenceReadOnly) {
      if (isEvidencePath(caseDir, pathValue) && !isWritablePath(caseDir, pathValue)) {
        return `refusing ${exec.name}: evidence and capture files are read-only (${pathValue})`
      }
    }
  }

  if (!SHELL_TOOLS.has(exec.name)) return undefined
  const command = stringArg(exec.arguments, ['command'])
  if (command === undefined) return undefined
  const workdir = stringArg(exec.arguments, ['workdir', 'cwd', 'working_directory'])
  if (workdir !== undefined && !isInsideCase(caseDir, workdir)) {
    return `refusing ${exec.name}: working directory ${workdir} is outside the case directory ${caseDir}`
  }
  return denyCommand(command, caseDir, evidenceReadOnly)
}

/**
 * Why a shell command must be denied.
 * @param command - bash or pwsh command text.
 * @param caseDir - absolute case directory.
 * @param evidenceReadOnly - when true, redirects onto evidence are denied.
 * @returns a model-facing deny reason, or undefined.
 */
export function denyCommand(
  command: string,
  caseDir: string,
  evidenceReadOnly: boolean,
): string | undefined {
  const tokens = tokenizeCommand(command)
  const head = tokens[0]
  if (head === undefined) return undefined
  const program = basenameToken(head)
  if (MALWARE_RUNNERS.test(program)) {
    return `refusing shell: ${program} would execute or emulate a binary; evidence stays read-only`
  }
  if (program === 'chmod' && tokens.includes('+x') && tokens.some(token => refersToEvidence(token, caseDir))) {
    return 'refusing shell: do not make evidence files executable'
  }
  for (const token of tokens) {
    if (EXECUTABLE_EVIDENCE.test(token) && refersToEvidence(token, caseDir)) {
      return `refusing shell: do not execute captured binaries (${token})`
    }
  }
  if (evidenceReadOnly && commandWritesEvidence(command, tokens, caseDir)) {
    return 'refusing shell: evidence and capture files are read-only'
  }
  for (const [index, token] of tokens.entries()) {
    if (index === 0 || !looksLikePath(token)) continue
    if (isSystemBin(token)) continue
    if (!isInsideCase(caseDir, token)) {
      return `refusing shell: ${token} is outside the case directory ${caseDir}`
    }
  }
  return undefined
}

/**
 * First defined string among candidates, or undefined when all are missing.
 * @param values - capture groups or other optional strings.
 * @returns the first defined value.
 */
export function firstDefined(...values: Array<string | undefined>): string | undefined {
  return values.find((value): value is string => value !== undefined)
}

/** Last path segment of a program token, ignoring a Windows drive prefix. */
function basenameToken(token: string): string {
  const slash = Math.max(token.lastIndexOf('/'), token.lastIndexOf('\\'))
  return slash === -1 ? token : token.slice(slash + 1)
}

/** Whether a token names a system executable rather than a case file. */
function isSystemBin(token: string): boolean {
  return token.startsWith('/usr/') || token.startsWith('/bin/') || token.startsWith('/sbin/')
}

/** Whether a token resolves under `evidence/` or is an evidence-suffix file in the case. */
function refersToEvidence(token: string, caseDir: string): boolean {
  if (!looksLikePath(token) && !EXECUTABLE_EVIDENCE.test(token)) return false
  try {
    return isEvidencePath(caseDir, token)
  } catch {
    return token.includes('evidence') || EXECUTABLE_EVIDENCE.test(token)
  }
}

/** Whether the command redirects or tees onto an evidence path. */
function commandWritesEvidence(command: string, tokens: readonly string[], caseDir: string): boolean {
  if (/(?:>>?|tee(?:\s+-a)?)\s+\S*evidence\S*/i.test(command)) return true
  for (const [index, token] of tokens.entries()) {
    const previous = tokens[index - 1]
    if (previous !== '>' && previous !== '>>' && previous !== 'tee') continue
    if (!isInsideCase(caseDir, token)) continue
    if (isEvidencePath(caseDir, token)) return true
  }
  return false
}

/** Re-export containment helpers used by the tools package. */
export { isEvidencePath, isInsideCase, isWritablePath, looksLikePath, resolveInsideCase }
