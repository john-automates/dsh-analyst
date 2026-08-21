/**
 * Case-scoped investigation ledger: harvest unique labeled identities from
 * tool results, auto-issue hunts after new identities, auto-run outstanding
 * issued hunts through `pcap_filter`, deny writes to evidence and work
 * outside the case directory, and persist a 5W1H close packet.
 *
 * State is folded from the session log. There is no live mirror.
 *
 * @module @deepseek-ai/dsh-investigation
 */

import { readdir } from 'node:fs/promises'
import { extname, isAbsolute, join, resolve } from 'node:path'
import { Context, Service } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { boundContextSummary, createUserMessage } from '@deepseek-ai/dsh-llm'
import type { Session, SessionEvent, UserMessage } from '@deepseek-ai/dsh-session'
import type {
  PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult, ToolRunContext,
} from '@deepseek-ai/dsh-tools'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type {} from '@deepseek-ai/dsh-agent'
import { harvestIdentities, identityKey } from './harvest.ts'
import {
  evidenceTextForHunts, formatLedger, huntFilterSpec, huntNotice, huntsForNewIdentities,
  huntsToAutoRun, huntKey,
} from './hunts.ts'
import { denyReason, stringArg } from './policy.ts'
import { isEvidencePath, isInsideCase, isWritablePath, resolveInsideCase } from './paths.ts'
import type { CaseReport, Hunt, Identity } from './types.ts'

export type * from './types.ts'
export type { HuntFilterSpec } from './hunts.ts'
export {
  decodeUtf16LeHex, harvestIdentities, identityKey, identityOf, IDENTITY_LABELS, normalizeIdentityValue,
} from './harvest.ts'
export {
  c2TalkingLanIps, displayFilterFor, evidenceTextForHunts, foldToolResultText, formatLedger,
  huntFilterSpec, huntKey, huntNotice, huntsForNewIdentities, huntsToAutoRun, isLanIpv4,
  isNonLanUnicastIpv4, shouldAutoRunHunt,
} from './hunts.ts'
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
   * When true, a new IP issues eth.src, name-service, Kerberos CNameString, and
   * SAMR QueryUserInfo hunts; a new hostname issues Kerberos and SAMR; a new
   * user issues SAMR QueryUserInfo. After a LAN IP talks to a non-LAN peer,
   * those identity hunts issue only for that C2-talking IP. Outstanding issued
   * hunts then run through `pcap_filter` with the scoped display_filter and
   * fields; results harvest into the ledger. Non-LAN / C2 IP subjects do not
   * auto-run. Defaults to true.
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
  /** Whether new IP/hostname/user identities auto-issue and auto-run hunts. */
  readonly autoHunt: boolean
  /** Hunt keys already auto-run (or attempted) on one session. */
  private readonly executedHuntKeys = new WeakMap<Session, Set<string>>()

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
      const notices = await this.observe(exec, result)
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

  /** Harvest identities, issue hunts, and auto-run outstanding issued hunts. */
  private async observe(exec: ToolExecution, result: ToolExecutionResult): Promise<UserMessage | undefined> {
    if (result.isError || exec.agent === undefined) return undefined
    const session = exec.agent.session
    const current = resultText(result)
    const added: Identity[] = []
    const issued: Hunt[] = []
    const evidence = (): string => evidenceTextForHunts(session.events, current)
    const harvestFrom = (text: string, evidenceText: string): void => {
      for (const identity of harvestIdentities(text, evidenceText)) {
        if (this.recordIdentity(session, identity)) added.push(identity)
      }
    }
    const issueFrom = (batch: readonly Identity[]): void => {
      if (!this.autoHunt) return
      for (const hunt of huntsForNewIdentities(batch, foldHunts(session.events), evidence())) {
        this.recordHunt(session, hunt)
        issued.push(hunt)
      }
    }
    harvestFrom(current, evidence())
    issueFrom(added)
    if (this.autoHunt) {
      await this.autoRunOutstanding(exec, session, current, (text) => {
        const before = added.length
        harvestFrom(text, `${evidence()}\n${text}`)
        issueFrom(added.slice(before))
      })
    }
    if (added.length === 0) return undefined
    const lines = [
      ...added.map(identity => `New identity: ${identity.label} ${identity.value}.`),
      ...issued.map(huntNotice),
    ]
    const first = added[0]
    const headline = first !== undefined && added.length === 1
      ? `New identity: ${first.label} ${first.value}`
      : `New identities: ${added.map(identity => identity.label).join(', ')}`
    return createUserMessage({
      content: [{ type: 'text', text: lines.join('\n') }],
      source: {
        kind: 'plugin',
        plugin: 'investigation',
        form: 'notice',
        summary: boundContextSummary(headline),
      },
    })
  }

  /**
   * Execute outstanding eligible hunts through `pcap_filter` and harvest each dump.
   * @param exec - the triggering tool execution (path and cancellation).
   * @param session - session whose issued hunts are folded.
   * @param current - text of the triggering tool result.
   * @param onText - harvest and issue from one successful hunt dump.
   */
  private async autoRunOutstanding(
    exec: ToolExecution,
    session: Session,
    current: string,
    onText: (text: string) => void,
  ): Promise<void> {
    const tool = this.ctx.tools.get('pcap_filter', exec.agent)
    if (tool === undefined) return
    const path = await capturePathForAutoRun(this.caseDir, exec)
    if (path === undefined) return
    const executed = executedSet(this.executedHuntKeys, session)
    const runContext = autoRunContext(exec)
    for (;;) {
      const hunt = huntsToAutoRun(
        foldHunts(session.events),
        evidenceTextForHunts(session.events, current),
        executed,
      )[0]
      if (hunt === undefined) break
      executed.add(huntKey(hunt))
      const spec = huntFilterSpec(hunt)
      const args: Record<string, unknown> = { path, display_filter: spec.display_filter }
      if (spec.fields.length > 0) args.fields = [...spec.fields]
      let value: unknown
      try {
        value = await tool.execute(args, runContext)
      } catch {
        // pcap_filter / tshark failed; the triggering result must still succeed.
        continue
      }
      const text = huntResultText(value)
      if (text !== '') onText(text)
    }
  }
}

/** Capture suffixes auto-run will open. `.log` is evidence but not a pcap. */
const CAPTURE_EXTENSIONS = new Set(['.pcap', '.pcapng', '.cap'])

/**
 * Session-local set of hunt keys already auto-run or attempted.
 * @param store - per-session executed keys.
 * @param session - session whose hunts are being executed.
 * @returns the mutable set for this session.
 */
function executedSet(store: WeakMap<Session, Set<string>>, session: Session): Set<string> {
  const existing = store.get(session)
  if (existing !== undefined) return existing
  const created = new Set<string>()
  store.set(session, created)
  return created
}

/**
 * Run-context for a plugin-owned `pcap_filter` body. Auto-run is not a model call.
 * @param exec - the triggering execution (signal, agent, token).
 * @returns a context that does not defer notices or conclude the turn.
 */
function autoRunContext(exec: ToolExecution): ToolRunContext {
  return {
    ...exec,
    deferContext() {
      // Plugin harvest records identities; this body has no deferred context.
    },
    concludeTurn() {
      // Auto-run must not end the triggering turn.
    },
  }
}

/**
 * Read rendered text from a `pcap_filter` return value.
 * @param value - canonical tool value.
 * @returns dump text, or empty when the value has none.
 */
function huntResultText(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'object' && value !== null && 'text' in value) {
    const text = Reflect.get(value, 'text')
    if (typeof text === 'string') return text
  }
  return ''
}

/**
 * Capture path for auto-run: the triggering pcap tool's `path`, else the first
 * `*.pcap` / `*.pcapng` / `*.cap` under `evidence/` or the case root.
 * @param caseDir - absolute case directory.
 * @param exec - triggering execution that may name a capture.
 * @returns a case-relative or absolute capture path, or undefined when none exists.
 */
async function capturePathForAutoRun(caseDir: string, exec: ToolExecution): Promise<string | undefined> {
  const fromExec = stringArg(exec.arguments, ['path'])
  if (fromExec !== undefined && CAPTURE_EXTENSIONS.has(extname(fromExec).toLowerCase())) {
    return fromExec
  }
  const evidence = await firstCaptureIn(join(caseDir, 'evidence'), 'evidence')
  if (evidence !== undefined) return evidence
  return firstCaptureIn(caseDir, '')
}

/**
 * First capture filename in a directory, sorted.
 * @param abs - absolute directory to list.
 * @param relDir - case-relative prefix, or empty for the case root.
 * @returns a case-relative path, or undefined when the directory is missing or empty of captures.
 */
async function firstCaptureIn(abs: string, relDir: string): Promise<string | undefined> {
  let entries
  try {
    entries = await readdir(abs, { withFileTypes: true })
  } catch {
    // Missing evidence/ or unreadable directory: try the next location.
    return undefined
  }
  const names = entries
    .filter(entry => entry.isFile() && CAPTURE_EXTENSIONS.has(extname(entry.name).toLowerCase()))
    .map(entry => entry.name)
    .sort()
  const first = names[0]
  if (first === undefined) return undefined
  return relDir === '' ? first : `${relDir}/${first}`
}

export default Investigation
