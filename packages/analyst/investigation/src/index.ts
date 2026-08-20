/**
 * Case-scoped investigation ledger: harvest unique labeled identities from
 * tool results, auto-issue Kerberos then SAMR hunts, deny writes to evidence
 * and work outside the case directory, and persist a 5W1H close packet.
 *
 * State is folded from the session log. There is no live mirror.
 *
 * @module @deepseek-ai/dsh-investigation
 */

import { isAbsolute, resolve } from 'node:path'
import { Context, Service } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { boundContextSummary, createUserMessage } from '@deepseek-ai/dsh-llm'
import type { Session, SessionEvent, UserMessage } from '@deepseek-ai/dsh-session'
import type { PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type {} from '@deepseek-ai/dsh-agent'
import { harvestIdentities, identityKey } from './harvest.ts'
import { formatLedger, huntNotice, huntsForNewIdentities, huntKey } from './hunts.ts'
import { denyReason } from './policy.ts'
import { isEvidencePath, isInsideCase, isWritablePath, resolveInsideCase } from './paths.ts'
import type { CaseReport, Hunt, Identity } from './types.ts'

export type * from './types.ts'
export {
  decodeUtf16LeHex, harvestIdentities, identityKey, identityOf, IDENTITY_LABELS, normalizeIdentityValue,
} from './harvest.ts'
export { formatLedger, huntKey, huntNotice, huntsForNewIdentities } from './hunts.ts'
export {
  denyCommand, denyReason, stringArg, tokenizeCommand,
} from './policy.ts'
export {
  isEvidencePath, isInsideCase, isWritablePath, looksLikePath, relativeEscapesRoot, resolveInsideCase,
} from './paths.ts'

/** Methodology rendered as the `investigation:policy` prompt section. */
export const METHODOLOGY_SECTION = [
  'You are a network-security investigation analyst, not a coding agent.',
  'Define the Investigation Question (DINQ) before collecting more evidence.',
  'State who, what, when, where, why, and how (5W1H) as claims you can support with packets or logs.',
  'Work evidence-first and question-driven: every tool call answers a named question.',
  'Label unverified ideas as hunches and verify them in this case.',
  'Evidence under evidence/ and capture files (*.pcap, *.pcapng, *.cap, *.log) is read-only.',
  'Do not execute malware, run captured binaries, or operate on paths outside the case directory.',
  'Use pcap_info, pcap_filter, and logs.',
  'Valid tshark 4.4.16 fields include kerberos.CNameString, samr.samr_UserInfo21.account_name, and samr.samr_UserInfo21.full_name.',
  'Do not use ldap.sAMAccountName, ldap.displayName, kerberos.username, or samr.full_name — those fields are invalid.',
  'After a hostname or IP appears, hunt Kerberos CNameString, then SAMR QueryUserInfo for the display name.',
  'SAMR full_name is UTF-16 (for example Becka Rolf), not an LDAP displayName.',
  'Close with case_report using the 5W1H fields once the Investigation Question is answered.',
].join(' ')

/** Plugin config: one case directory and the two enforcement switches. */
export interface Config {
  /** Absolute directory that owns this case's evidence, notes, and report. */
  caseDir: string
  /** When true, evidence and capture files cannot be written or executed. Defaults to true. */
  evidenceReadOnly?: boolean
  /**
   * When true, a new IP or hostname issues Kerberos CNameString and SAMR QueryUserInfo hunts;
   * a new user issues SAMR QueryUserInfo. Defaults to true.
   */
  autoHunt?: boolean
}

/** Complete config after schemastery applies every field default. */
type ResolvedConfig = Required<Config>

/** Runtime schema for the investigation service. */
export const Config: z<Config> = z.object({
  caseDir: z.string().required(),
  evidenceReadOnly: z.boolean().default(true),
  autoHunt: z.boolean().default(true),
})

declare module '@deepseek-ai/cordis' {
  interface Context {
    investigation: Investigation
  }
}

/**
 * Require an absolute existing-or-creatable case directory string.
 * @param caseDir - raw config value.
 * @returns the resolved absolute path.
 */
export function resolveCaseDir(caseDir: string): string {
  if (typeof caseDir !== 'string' || caseDir.trim() === '') {
    throw new Error('InvestigationConfig needs a non-empty string `caseDir`')
  }
  if (!isAbsolute(caseDir)) {
    throw new Error('InvestigationConfig.caseDir must be an absolute path')
  }
  return resolve(caseDir)
}

/**
 * Fold unique identities from a log prefix.
 * @param events - session log or any prefix of it.
 * @returns identities in first-seen order.
 */
export function foldIdentities(events: readonly SessionEvent[]): Identity[] {
  const seen = new Set<string>()
  const out: Identity[] = []
  for (const event of events) {
    if (event.type !== 'investigation/identity') continue
    const key = identityKey(event.data)
    if (seen.has(key)) continue
    seen.add(key)
    out.push(event.data)
  }
  return out
}

/**
 * Fold unique hunts from a log prefix.
 * @param events - session log or any prefix of it.
 * @returns hunts in first-seen order.
 */
export function foldHunts(events: readonly SessionEvent[]): Hunt[] {
  const seen = new Set<string>()
  const out: Hunt[] = []
  for (const event of events) {
    if (event.type !== 'investigation/hunt') continue
    const key = huntKey(event.data)
    if (seen.has(key)) continue
    seen.add(key)
    out.push(event.data)
  }
  return out
}

/**
 * Fold the latest 5W1H report from a log prefix.
 * @param events - session log or any prefix of it.
 * @returns the last report, or undefined when none exists.
 */
export function foldReport(events: readonly SessionEvent[]): CaseReport | undefined {
  let report: CaseReport | undefined
  for (const event of events) {
    if (event.type === 'investigation/report') report = event.data
  }
  return report
}

/** Join rendered tool-result text blocks. */
function resultText(result: ToolExecutionResult): string {
  return result.content
    .filter((block): block is { type: 'text'; text: string } => block.type === 'text')
    .map(block => block.text)
    .join('\n')
}

/** Prepend one notice onto a post-execute decision. */
function withNotice(decision: PostToolDecision, notice: UserMessage): PostToolDecision {
  const additionalContexts = decision.additionalContexts === undefined
    ? [notice]
    : [notice, ...decision.additionalContexts]
  return { ...decision, additionalContexts }
}

/**
 * `ctx.investigation`: case-scoped identity ledger, hunt issuance, evidence
 * policy, methodology prompt, and 5W1H report persistence.
 */
export class Investigation extends Service {
  static inject = ['tools', 'systemPrompt']
  static Config = Config

  /** Resolved absolute case directory. */
  readonly caseDir: string
  /** Whether evidence and capture files are read-only. */
  readonly evidenceReadOnly: boolean
  /** Whether new IP/hostname/user identities auto-issue hunts. */
  readonly autoHunt: boolean

  /**
   * @param ctx - Cordis context carrying tools and systemPrompt.
   * @param config - validated case directory and enforcement switches.
   */
  constructor(ctx: Context, config: Config) {
    super(ctx, 'investigation')
    const resolved = config as ResolvedConfig
    this.caseDir = resolveCaseDir(resolved.caseDir)
    this.evidenceReadOnly = resolved.evidenceReadOnly
    this.autoHunt = resolved.autoHunt

    ctx.on('tools/pre-execute', (exec, next): Promise<PreToolDecision> => {
      const reason = denyReason(exec, this.caseDir, this.evidenceReadOnly)
      if (reason !== undefined) return Promise.resolve({ kind: 'deny', reason })
      return next()
    })

    ctx.on('tools/post-execute', async (exec, result, next): Promise<PostToolDecision> => {
      const notices = this.observe(exec, result)
      const downstream = await next()
      if (notices === undefined) return downstream
      return withNotice(downstream, notices)
    })

    ctx.systemPrompt.section({
      name: 'investigation:policy',
      order: 40,
      text: METHODOLOGY_SECTION,
    })

    ctx.systemPrompt.context({
      name: 'investigation:ledger',
      order: 200,
      text: (context) => {
        if (context.agent === undefined) return ''
        return formatLedger(
          foldIdentities(context.agent.session.events),
          foldHunts(context.agent.session.events),
          foldReport(context.agent.session.events),
        )
      },
    })
  }

  /**
   * Identities already on a session log.
   * @param session - session whose log is folded.
   * @returns unique identities in first-seen order.
   */
  identities(session: Session): Identity[] {
    return foldIdentities(session.events)
  }

  /**
   * Hunts already on a session log.
   * @param session - session whose log is folded.
   * @returns unique hunts in first-seen order.
   */
  hunts(session: Session): Hunt[] {
    return foldHunts(session.events)
  }

  /**
   * Latest 5W1H report on a session log.
   * @param session - session whose log is folded.
   * @returns the last report, or undefined.
   */
  report(session: Session): CaseReport | undefined {
    return foldReport(session.events)
  }

  /**
   * Append one identity when kind+value is new.
   * @param session - session to append to.
   * @param identity - identity to record.
   * @returns true when a new event was appended.
   */
  recordIdentity(session: Session, identity: Identity): boolean {
    if (foldIdentities(session.events).some(existing => identityKey(existing) === identityKey(identity))) {
      return false
    }
    session.append('investigation/identity', identity)
    return true
  }

  /**
   * Append one hunt when kind+subject is new.
   * @param session - session to append to.
   * @param hunt - hunt to record.
   * @returns true when a new event was appended.
   */
  recordHunt(session: Session, hunt: Hunt): boolean {
    if (foldHunts(session.events).some(existing => huntKey(existing) === huntKey(hunt))) return false
    session.append('investigation/hunt', hunt)
    return true
  }

  /**
   * Append a whole-value 5W1H close packet.
   * @param session - session to append to.
   * @param report - 5W1H fields.
   */
  recordReport(session: Session, report: CaseReport): void {
    session.append('investigation/report', report)
  }

  /**
   * Resolve a path and require it to stay inside the case directory.
   * @param target - absolute or case-relative path.
   * @returns the resolved absolute path.
   */
  resolveInsideCase(target: string): string {
    return resolveInsideCase(this.caseDir, target)
  }

  /**
   * Whether a path is read-only evidence.
   * @param target - absolute or case-relative path.
   * @returns true when writes must be denied.
   */
  isEvidence(target: string): boolean {
    return isEvidencePath(this.caseDir, target)
  }

  /**
   * Whether a path may be written while evidence stays read-only.
   * @param target - absolute or case-relative path.
   * @returns true for `notes/` descendants and case-root `report.md`.
   */
  isWritable(target: string): boolean {
    return isWritablePath(this.caseDir, target)
  }

  /**
   * Whether a path stays inside the case directory.
   * @param target - absolute or case-relative path.
   * @returns true when the resolved path is the case root or a descendant.
   */
  contains(target: string): boolean {
    return isInsideCase(this.caseDir, target)
  }

  /** Harvest identities and issue hunts from one successful tool result. */
  private observe(exec: ToolExecution, result: ToolExecutionResult): UserMessage | undefined {
    if (result.isError || exec.agent === undefined) return undefined
    const session = exec.agent.session
    const added: Identity[] = []
    for (const identity of harvestIdentities(resultText(result))) {
      if (this.recordIdentity(session, identity)) added.push(identity)
    }
    if (added.length === 0) return undefined
    const lines = added.map(identity => `New identity: ${identity.label} ${identity.value}.`)
    if (this.autoHunt) {
      for (const hunt of huntsForNewIdentities(added, foldHunts(session.events))) {
        this.recordHunt(session, hunt)
        lines.push(huntNotice(hunt))
      }
    }
    const text = lines.join('\n')
    const first = added[0]
    const headline = first !== undefined && added.length === 1
      ? `New identity: ${first.label} ${first.value}`
      : `New identities: ${added.map(identity => identity.label).join(', ')}`
    return createUserMessage({
      content: [{ type: 'text', text }],
      source: {
        kind: 'plugin',
        plugin: 'investigation',
        form: 'notice',
        summary: boundContextSummary(headline),
      },
    })
  }
}

export default Investigation
