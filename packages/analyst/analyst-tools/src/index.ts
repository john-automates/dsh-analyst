/**
 * Model-facing SOC/NSM tools over a case-scoped investigation ledger.
 * Named exports preserve loader injection metadata; there is no default export.
 * @module @deepseek-ai/dsh-analyst-tools
 */

import { execFile } from 'node:child_process'
import { readFile, stat } from 'node:fs/promises'
import { promisify } from 'node:util'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import {
  caseReportDenyReason, foldToolResultText, requireCaseReport,
} from '@deepseek-ai/dsh-investigation'
import { coercePcapFilterFields, rejectInvalidTsharkFields, unwrapPcapDisplayFilter } from './fields.ts'

export { INVALID_TSHARK_FIELDS, RECOMMENDED_TSHARK_FIELDS, rejectInvalidTsharkFields } from './fields.ts'

const execFileAsync = promisify(execFile)

export const name = 'analyst-tools'
export const inject = ['tools', 'investigation']

/** Deployment-owned binaries, output cap, and command deadline. */
export interface Config {
  /** Maximum characters returned from a pcap or log tool. Defaults to 32000. */
  maxOutputChars?: number
  /** Deadline in milliseconds for one tshark or capinfos process. Defaults to 60000. */
  commandTimeoutMs?: number
  /** `tshark` executable used by `pcap_filter` and as a `pcap_info` fallback. */
  tsharkBin?: string
  /** `capinfos` executable used by `pcap_info`. */
  capinfosBin?: string
}

/** Complete config after schemastery applies every field default. */
type ResolvedConfig = Required<Config>

/** Runtime schema for the analyst tool consumer. */
export const Config: z<Config> = z.object({
  maxOutputChars: z.number().min(1).default(32000),
  commandTimeoutMs: z.number().min(1).default(60000),
  tsharkBin: z.string().default('tshark'),
  capinfosBin: z.string().default('capinfos'),
})

const CASE_IDENTITY_SLOT_SCHEMA = {
  type: 'object' as const,
  additionalProperties: false as const,
  properties: {
    entity_id: { type: 'string' as const, required: true as const },
    ip: { type: 'string' as const },
    mac: { type: 'string' as const },
    hostname: { type: 'string' as const },
    user: { type: 'string' as const },
    full_name: { type: 'string' as const },
  },
}

const CASE_REPORT_SLOT_INPUT = {
  type: 'object' as const,
  additionalProperties: false as const,
  properties: {
    entity_id: {
      type: 'string' as const,
      description: 'Bound victim address, or a user, hostname, MAC, or full_name on that victim row.',
    },
    ip: { type: 'string' as const, description: 'Victim IPv4 when known. Omitted after a live bind is filled from the victim row.' },
    mac: { type: 'string' as const, description: 'Victim MAC when it belongs to the victim entity. Omitted after a live bind is filled from the victim row.' },
    hostname: { type: 'string' as const, description: 'Victim hostname when it belongs to the victim entity. Omitted after a live bind is filled from the victim row.' },
    user: { type: 'string' as const, description: 'Victim user when it belongs to the victim entity. Omitted after a live bind is filled from the victim row.' },
    full_name: { type: 'string' as const, description: 'Victim full name when it belongs to the victim entity. Omitted after a live bind is filled from the victim row.' },
  },
}

const CASE_REPORT_SLOT_DESCRIPTION = [
  'Optional victim-row handle.',
  'The bound victim address, or a user, hostname, MAC, or full_name on that row.',
  'A victim-row handle string is the same handle after a live bind.',
  'A JSON object string with entity_id is the same handle.',
  'Omitted keys are filled from the projected victim row after a live bind.',
  'Unmatched free-text who or where is denied.',
].join(' ')

/**
 * Render a projected who/where slot as one line.
 * @param slot - victim entity row.
 * @returns space-joined identity values, or the entity id when the row is empty.
 */
function renderIdentitySlot(slot: {
  entity_id: string
  ip?: string
  mac?: string
  hostname?: string
  user?: string
  full_name?: string
}): string {
  const parts = [slot.ip, slot.mac, slot.hostname, slot.user, slot.full_name].filter(
    (part): part is string => part !== undefined && part !== '',
  )
  return parts.length === 0 ? slot.entity_id : parts.join(' ')
}

const PCAP_FILTER_DESCRIPTION = [
  'Filter a pcap/pcapng in the case directory with tshark.',
  'Use display_filter for Wireshark display filters and fields for `-e` field names.',
  'Valid tshark 4.4.16 identity fields include kerberos.CNameString, samr.samr_UserInfo21.account_name, and samr.samr_UserInfo21.full_name.',
  'Invalid fields (rejected): ldap.sAMAccountName, ldap.displayName, kerberos.username, samr.full_name.',
  'After a hostname or IP, hunt kerberos.CNameString, then SAMR QueryUserInfo for the display name.',
  'SAMR full_name is UTF-16LE (Becka Rolf is the worked example), not LDAP displayName.',
].join(' ')

/**
 * Join stdout/stderr from a failed helper. Missing streams become empty.
 * @param failure - execFile error that may carry captured streams.
 * @returns trimmed combined text.
 */
export function helperFailureText(failure: { stdout?: unknown; stderr?: unknown }): string {
  const stdout = typeof failure.stdout === 'string' ? failure.stdout : ''
  const stderr = typeof failure.stderr === 'string' ? failure.stderr : ''
  return stderr === '' ? stdout : `${stdout}\n${stderr}`.trim()
}

/**
 * Clip tool output to the configured character budget.
 * @param text - complete command or file text.
 * @param maxOutputChars - inclusive character cap.
 * @returns the original text, or a prefix plus a truncation notice.
 */
export function clipOutput(text: string, maxOutputChars: number): string {
  if (text.length <= maxOutputChars) return text
  return `${text.slice(0, maxOutputChars)}\n[truncated: ${text.length - maxOutputChars} more characters]`
}

/**
 * Format tshark `-T fields` rows so harvest can read labeled values.
 * @param fields - `-e` field names, in column order.
 * @param stdout - raw tshark stdout.
 * @returns one labeled line per packet row.
 */
export function formatFieldRows(fields: readonly string[], stdout: string): string {
  const lines = stdout.split(/\r?\n/).filter(line => line !== '')
  if (fields.length === 0) return stdout
  return lines.map((line) => {
    const columns = line.split('\t')
    return fields.map((field, index) => `${field}: ${columns[index] ?? ''}`).join('\t')
  }).join('\n')
}

/** Error raised by a spawned pcap helper. */
interface ExecFileError extends Error {
  code?: string | number
  killed?: boolean
  signal?: NodeJS.Signals | number
  stdout?: string
  stderr?: string
}

/**
 * Run one helper without a shell, honoring the tool signal and case cwd.
 * @param bin - executable path or PATH name.
 * @param args - argv after the executable.
 * @param options - case directory, deadline, output cap, and cancellation.
 * @returns clipped stdout, with stderr appended when present.
 */
export async function runHelper(
  bin: string,
  args: readonly string[],
  options: {
    cwd: string
    timeoutMs: number
    maxOutputChars: number
    signal: AbortSignal
  },
): Promise<string> {
  try {
    const { stdout, stderr } = await execFileAsync(bin, [...args], {
      cwd: options.cwd,
      timeout: options.timeoutMs,
      maxBuffer: options.maxOutputChars * 4,
      signal: options.signal,
      windowsHide: true,
    })
    const combined = stderr === '' ? stdout : `${stdout}\n${stderr}`
    return clipOutput(combined, options.maxOutputChars)
  } catch (error) {
    if (options.signal.aborted) throw new Error(`${bin} was cancelled`)
    const failure = error as ExecFileError
    if (failure.code === 'ENOENT') throw new Error(`${bin} is not installed or not on PATH`)
    if (failure.killed === true || failure.code === 'ETIMEDOUT') {
      throw new Error(`${bin} exceeded commandTimeoutMs (${options.timeoutMs})`)
    }
    const combined = helperFailureText(failure)
    if (combined !== '') return clipOutput(combined, options.maxOutputChars)
    throw new Error(`${bin} failed: ${failure.message}`)
  }
}

/**
 * Register pcap_info, pcap_filter, logs, and case_report on `ctx.tools`.
 * bind_relationship is registered by the investigation service.
 * @param ctx - registrant context carrying tools and investigation.
 * @param config - binaries, output cap, and command deadline.
 */
export function apply(ctx: Context, config: Config): void {
  const investigation = ctx.investigation
  const resolved = config as ResolvedConfig
  const maxOutputChars = resolved.maxOutputChars
  const commandTimeoutMs = resolved.commandTimeoutMs

  ctx.tools.register(defineTool({
    name: 'pcap_info',
    description: 'Summarize a pcap/pcapng in the case directory with capinfos (or tshark if capinfos is missing). The file stays read-only.',
    parameters: {
      path: { type: 'string', required: true, description: 'Case-relative or absolute path of the capture file.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
      render: (_args, value) => [{ type: 'text', text: value.text }],
    },
    isConcurrencySafe: () => true,
    execute: async (args, exec) => {
      const file = await existingFile(investigation.resolveInsideCase(args.path))
      const helper = {
        cwd: investigation.caseDir,
        timeoutMs: commandTimeoutMs,
        maxOutputChars,
        signal: exec.signal,
      }
      try {
        return { text: await runHelper(resolved.capinfosBin, ['-T', '-M', file], helper) }
      } catch (error) {
        if (!(error instanceof Error) || !error.message.includes('is not installed')) throw error
        return { text: await runHelper(resolved.tsharkBin, ['-r', file, '-q'], helper) }
      }
    },
    presentCall: args => ({ card: 'generic', title: 'pcap info', kind: 'other', rawInput: args.path }),
  }))

  ctx.tools.register(defineTool({
    name: 'pcap_filter',
    description: PCAP_FILTER_DESCRIPTION,
    parameters: {
      path: { type: 'string', required: true, description: 'Case-relative or absolute path of the capture file.' },
      display_filter: { type: 'string', description: 'Wireshark display filter, for example kerberos.CNameString.' },
      fields: {
        description: 'tshark `-e` field names. A string is one field or a comma/space-separated list. Invalid tshark 4.4.16 fields are rejected before spawn.',
        oneOf: [
          { type: 'string' },
          { type: 'array', items: { type: 'string' } },
        ],
      },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
      render: (_args, value) => [{ type: 'text', text: value.text }],
    },
    isConcurrencySafe: () => true,
    execute: async (args, exec) => {
      const file = await existingFile(investigation.resolveInsideCase(args.path))
      const displayFilter = unwrapPcapDisplayFilter(args.display_filter)
      const fields = rejectInvalidTsharkFields(coercePcapFilterFields(args.fields))
      const argv = ['-r', file]
      if (displayFilter !== undefined) {
        argv.push('-Y', displayFilter)
      }
      if (fields.length > 0) {
        argv.push('-T', 'fields')
        for (const field of fields) argv.push('-e', field)
      }
      const stdout = await runHelper(resolved.tsharkBin, argv, {
        cwd: investigation.caseDir,
        timeoutMs: commandTimeoutMs,
        maxOutputChars,
        signal: exec.signal,
      })
      return { text: fields.length > 0 ? formatFieldRows(fields, stdout) : stdout }
    },
    presentCall: args => ({
      card: 'generic',
      title: 'pcap filter',
      kind: 'other',
      rawInput: { path: args.path, display_filter: args.display_filter, fields: args.fields },
    }),
  }))

  ctx.tools.register(defineTool({
    name: 'logs',
    description: 'Read a log or text file in the case directory. The file stays read-only.',
    parameters: {
      path: { type: 'string', required: true, description: 'Case-relative or absolute path of the log file.' },
      start_line: { type: 'integer', description: '1-based first line to return. Defaults to 1.' },
      max_lines: { type: 'integer', description: 'Maximum lines to return. Defaults to the rest of the file, still clipped by maxOutputChars.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
      render: (_args, value) => [{ type: 'text', text: value.text }],
    },
    isConcurrencySafe: () => true,
    execute: async (args) => {
      const file = await existingFile(investigation.resolveInsideCase(args.path))
      const raw = await readFile(file, 'utf8')
      const lines = raw.split(/\r?\n/)
      const start = Math.max((args.start_line ?? 1) - 1, 0)
      const end = args.max_lines === undefined ? lines.length : start + Math.max(args.max_lines, 0)
      return { text: clipOutput(lines.slice(start, end).join('\n'), maxOutputChars) }
    },
    presentCall: args => ({ card: 'generic', title: 'logs', kind: 'other', rawInput: args.path }),
  }))

  ctx.tools.register(defineTool({
    name: 'case_report',
    description: [
      'Close the investigation with a 5W1H packet after bind_relationship.',
      'who and where are projections of the bound victim entity row; do not fill them as free text.',
      'Send evidenced what, when, why, and how. This replaces any previous case_report on the session log.',
    ].join(' '),
    parameters: {
      what: { type: 'string', required: true, description: 'What happened.' },
      when: { type: 'string', required: true, description: 'When it happened.' },
      why: { type: 'string', required: true, description: 'Why it happened, as evidenced.' },
      how: { type: 'string', required: true, description: 'How it happened, as evidenced.' },
      who: {
        description: CASE_REPORT_SLOT_DESCRIPTION,
        oneOf: [
          CASE_REPORT_SLOT_INPUT,
          { type: 'string' },
        ],
      },
      where: {
        description: CASE_REPORT_SLOT_DESCRIPTION,
        oneOf: [
          CASE_REPORT_SLOT_INPUT,
          { type: 'string' },
        ],
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          who: { ...CASE_IDENTITY_SLOT_SCHEMA, required: true as const },
          what: { type: 'string', required: true },
          when: { type: 'string', required: true },
          where: { ...CASE_IDENTITY_SLOT_SCHEMA, required: true as const },
          why: { type: 'string', required: true },
          how: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: [
          'Case report recorded.',
          `Who: ${renderIdentitySlot(value.who)}`,
          `What: ${value.what}`,
          `When: ${value.when}`,
          `Where: ${renderIdentitySlot(value.where)}`,
          `Why: ${value.why}`,
          `How: ${value.how}`,
        ].join('\n'),
      }],
    },
    execute: (args, exec) => {
      if (exec.agent === undefined) throw new Error('case_report requires an owning agent session')
      const claims = {
        what: args.what.trim(),
        when: args.when.trim(),
        why: args.why.trim(),
        how: args.how.trim(),
      }
      for (const [field, value] of Object.entries(claims)) {
        if (value === '') throw new Error(`case_report ${field} must be a non-empty string`)
      }
      const session = exec.agent.session
      const bind = ctx.investigation.bind(session)
      const identities = ctx.investigation.identities(session)
      const evidenceText = foldToolResultText(session.events)
      const denied = caseReportDenyReason(args, bind, identities, evidenceText)
      if (denied !== undefined) throw new Error(denied)
      const report = requireCaseReport(bind, identities, claims, evidenceText, {
        who: args.who,
        where: args.where,
      })
      ctx.investigation.recordReport(session, report)
      return Promise.resolve(report)
    },
    presentCall: args => ({ card: 'generic', title: 'Case report', kind: 'other', rawInput: args }),
  }))
}

/**
 * Require an existing regular file.
 * @param path - resolved absolute path inside the case.
 * @returns the same path.
 */
async function existingFile(path: string): Promise<string> {
  const info = await stat(path)
  if (!info.isFile()) throw new Error(`${path} is not a file`)
  return path
}
