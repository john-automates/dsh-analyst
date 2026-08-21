/**
 * Case-scoped investigation ledger: harvest unique labeled identities from
 * tool results, auto-issue hunts after new identities, auto-issue `other-end`
 * when bind_relationship assigns a cue as victim, auto-run outstanding
 * issued hunts through `pcap_filter`, deny writes to evidence and work
 * outside the case directory, require BindRelationship before case_report,
 * deny write/edit of case-root close files, and persist a 5W1H close packet
 * whose who/where project from the bound victim entity row.
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
import {
  defineTool,
  type PostToolDecision, type PreToolDecision, type ToolExecution, type ToolExecutionResult,
  type ToolRunContext,
} from '@deepseek-ai/dsh-tools'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type {} from '@deepseek-ai/dsh-agent'
import {
  caseReportDenyReason, ENDPOINT_ROLES, foldBind, formatRolesCard,
  otherEndHuntForDeniedBind, resolveBind, victimOf,
} from './bind.ts'
import { harvestIdentities, identityKey } from './harvest.ts'
import {
  c2TalkingLanIps, evidenceTextForHunts, foldToolResultText, huntFilterSpec, huntNotice,
  huntsForNewIdentities, huntsToAutoRun, huntKey,
} from './hunts.ts'
import { formatLedger } from './ledger.ts'
import { denyReason, stringArg } from './policy.ts'
import { isEvidencePath, isInsideCase, isWritablePath, resolveInsideCase } from './paths.ts'
import type { CaseReport, Hunt, Identity, RelationshipBind } from './types.ts'

export type * from './types.ts'
export type { HuntFilterSpec } from './hunts.ts'
export {
  decodeUtf16LeHex, harvestIdentities, identityKey, identityOf, IDENTITY_LABELS, normalizeIdentityValue,
} from './harvest.ts'
export {
  c2TalkingLanIps, displayFilterFor, evidenceTextForHunts, foldToolResultText,
  huntFilterSpec, huntKey, huntNotice, huntsForNewIdentities, huntsToAutoRun, isLanIpv4,
  isNonLanUnicastIpv4, otherEndDisplayFilter, otherEndHunt, shouldAutoRunHunt,
} from './hunts.ts'
export { formatLedger } from './ledger.ts'
export { c2TalkingLanVictim } from './report.ts'
export type { C2TalkingLanVictim } from './report.ts'
export {
  BOTH_LAN_CONVERSATION_REASON, caseReportDenyReason, coerceBindRequest, completeAcceptedSlot,
  cueVictimUnboundReason, defaultRoleForAddr, ENDPOINT_ROLES, ENDPOINTS_ARRAY_REASON,
  entityIdForIdentity, foldBind, formatRolesCard, identityDonatesToVictim, isCueObservationAddr,
  LAN_C2_REASON, normalizeEndpointAddr, otherEndHuntForDeniedBind, projectCaseReport,
  projectVictimSlot, requireCaseReport, resolveBind, roleForIdentity, UNBOUND_REASON, victimOf,
  VICTIM_COUNT_REASON,
} from './bind.ts'
export type {
  BindEndpointInput, BindRelationshipInput, BindRequest, BindResolution, CaseReportClaims,
  CoercedBindRequest, SubmittedIdentitySlots,
} from './bind.ts'
export {
  CLOSE_FILE_REASON, denyCommand, denyReason, stringArg, tokenizeCommand,
} from './policy.ts'
export {
  CASE_ROOT_CLOSE_FILES, isCaseRootClosePath, isEvidencePath, isInsideCase, isWritablePath,
  looksLikePath, relativeEscapesRoot, resolveInsideCase,
} from './paths.ts'

/** Methodology rendered as the `investigation:policy` prompt section. */
export const METHODOLOGY_SECTION = [
  'You are a network-security investigation analyst, not a coding agent.',
  'Define the Investigation Question (DINQ) before collecting more evidence.',
  'Before Who/Where, bind the conversation. The detector’s IP is a hypothesis about the other end until the bind says otherwise.',
  'Use bind_relationship to assign victim vs c2 on the cited conversation. Exactly one victim. The cited conversation must include a cue/observation address. Role c2 cannot be a LAN address. Cue and observation addresses default to c2 and cannot be victim.',
  'State what, when, why, and how as claims you can support with packets or logs. who and where are projections of the bound victim.',
  'Work evidence-first and question-driven: every tool call answers a named question.',
  'Label unverified ideas as hunches and verify them in this case.',
  'Evidence under evidence/ and capture files (*.pcap, *.pcapng, *.cap, *.log) is read-only.',
  'Do not execute malware, run captured binaries, or operate on paths outside the case directory.',
  'Use pcap_info, pcap_filter, logs, and bind_relationship.',
  'Valid tshark 4.4.16 fields include kerberos.CNameString, samr.samr_UserInfo21.account_name, and samr.samr_UserInfo21.full_name.',
  'Do not use ldap.sAMAccountName, ldap.displayName, kerberos.username, or samr.full_name — those fields are invalid.',
  'After a hostname or IP appears, hunt Kerberos CNameString, then SAMR QueryUserInfo for the display name.',
  'SAMR full_name is UTF-16 (for example Becka Rolf), not an LDAP displayName.',
  'Close with case_report only after bind_relationship has assigned the victim.',
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
   * those identity hunts issue only for that C2-talking IP. A cue-as-victim
   * bind issues `other-end` for that cue. Outstanding issued hunts then run
   * through `pcap_filter` with the scoped display_filter and fields; results
   * harvest into the ledger. Non-LAN / C2 IP subjects do not auto-run, except
   * `other-end`. Defaults to true.
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
 * First-seen kind+value wins the row. A later event may fill a missing
 * `evidence_id`, or overwrite a MAC DC/peer stamp when the later id is the
 * bound victim or a C2-talking LAN IP, so a field-only victim-IP `eth.src`
 * dump can restamp a wrong first harvest. A later DC/peer stamp does not
 * overwrite a victim or C2-talking stamp.
 * @param events - session log or any prefix of it.
 * @returns identities in first-seen order.
 */
export function foldIdentities(events: readonly SessionEvent[]): Identity[] {
  const seen = new Map<string, Identity>()
  const out: Identity[] = []
  const preferred = preferredMacEvidenceIds(events)
  for (const event of events) {
    if (event.type !== 'investigation/identity') continue
    const key = identityKey(event.data)
    const existing = seen.get(key)
    if (existing === undefined) {
      const copy = { ...event.data }
      seen.set(key, copy)
      out.push(copy)
      continue
    }
    const next = restampEvidenceId(existing, event.data, preferred)
    if (next !== undefined) existing.evidence_id = next
  }
  return out
}

/**
 * Later `evidence_id` that should overwrite the first-seen kind+value row.
 * A missing stamp fills from any later non-empty id. A MAC DC/peer stamp
 * overwrites only when the later id is the bound victim or a C2-talking
 * LAN IP. A victim or C2-talking stamp does not yield to a later DC/peer
 * stamp. Other kinds keep the first non-empty stamp.
 * @param existing - first-seen folded row.
 * @param incoming - later identity of the same kind+value.
 * @param preferred - bound victim and C2-talking LAN IPs on this log.
 * @returns the incoming id when the folded row must take it.
 */
function restampEvidenceId(
  existing: Identity,
  incoming: Identity,
  preferred: ReadonlySet<string>,
): string | undefined {
  const next = incoming.evidence_id
  if (next === undefined || next === '') return undefined
  const prev = existing.evidence_id
  if (prev === undefined || prev === '') return next
  if (existing.kind !== 'mac' || incoming.kind !== 'mac') return undefined
  if (preferred.has(prev)) return undefined
  return preferred.has(next) ? next : undefined
}

/**
 * IPv4s a later MAC harvest may restamp onto: the bound victim address
 * and every C2-talking LAN IP in tool-result text.
 * @param events - session log or any prefix of it.
 * @returns those IPv4s.
 */
function preferredMacEvidenceIds(events: readonly SessionEvent[]): Set<string> {
  const preferred = new Set(c2TalkingLanIps(foldToolResultText(events)))
  const bind = foldBind(events)
  const victim = bind === undefined ? undefined : victimOf(bind)
  if (victim !== undefined) preferred.add(victim.addr)
  return preferred
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
 * policy, BindRelationship, methodology prompt, and 5W1H report persistence.
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
      if (exec.name === 'case_report' || setsWhoWhere(exec.arguments)) {
        const session = exec.agent?.session
        const close = caseReportDenyReason(
          exec.arguments,
          session === undefined ? undefined : foldBind(session.events),
          session === undefined ? [] : foldIdentities(session.events),
          session === undefined ? '' : foldToolResultText(session.events),
        )
        if (close !== undefined) return Promise.resolve({ kind: 'deny', reason: close })
      }
      return next()
    })

    ctx.tools.register(defineTool({
      name: 'bind_relationship',
      description: BIND_RELATIONSHIP_DESCRIPTION,
      parameters: {
        src: { type: 'string', required: true, description: 'Conversation source address.' },
        dst: { type: 'string', required: true, description: 'Conversation destination address.' },
        dport: {
          required: true,
          description: 'Destination port. A numeric string that is an integer 1-65535 is the same port.',
          oneOf: [
            { type: 'integer' },
            { type: 'string' },
          ],
        },
        t: { type: 'string', required: true, description: 'Conversation time.' },
        evidence_id: { type: 'string', required: true, description: 'Id of the cited conversation evidence.' },
        endpoints: {
          required: true,
          description: [
            'Endpoints with role and because. Cue/observation addresses default to c2. Exactly one victim.',
            'Cite the LAN host talking to the cue/observation address, not a LAN DC/AD service.',
            'A JSON array string of endpoint objects is the same list.',
          ].join(' '),
          oneOf: [
            {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  addr: { type: 'string', required: true, description: 'Endpoint address.' },
                  role: {
                    type: 'string',
                    enum: [...ENDPOINT_ROLES],
                    description: 'victim, c2, infra, distractor, or unknown. Omitted cue/observation addresses default to c2.',
                  },
                  because: {
                    type: 'string',
                    required: true,
                    description: 'Why this role. A cue/observation address cannot be victim. Role c2 cannot be a LAN address.',
                  },
                },
              },
            },
            { type: 'string' },
          ],
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            src: { type: 'string', required: true },
            dst: { type: 'string', required: true },
            dport: { type: 'integer', required: true },
            t: { type: 'string', required: true },
            evidence_id: { type: 'string', required: true },
            endpoints: {
              type: 'array',
              required: true,
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  addr: { type: 'string', required: true },
                  role: { type: 'string', required: true, enum: [...ENDPOINT_ROLES] },
                  because: { type: 'string', required: true },
                },
              },
            },
          },
        },
        render: (_args, value) => [{
          type: 'text',
          text: formatRolesCard({
            relationship: {
              src: value.src, dst: value.dst, dport: value.dport, t: value.t, evidence_id: value.evidence_id,
            },
            endpoints: value.endpoints,
          }),
        }],
      },
      execute: async (args, exec) => {
        if (exec.agent === undefined) throw new Error('bind_relationship requires an owning agent session')
        const request = {
          relationship: {
            src: args.src, dst: args.dst, dport: args.dport, t: args.t, evidence_id: args.evidence_id,
          },
          endpoints: args.endpoints,
        }
        const resolved = resolveBind(request)
        if (!resolved.ok) {
          const hunt = otherEndHuntForDeniedBind(request)
          if (hunt !== undefined) {
            this.recordHunt(exec.agent.session, hunt)
            if (this.autoHunt) await this.harvestIssueAutoRun(exec, exec.agent.session, '')
          }
          throw new Error(resolved.reason)
        }
        this.recordBind(exec.agent.session, resolved.bind)
        return {
          ...resolved.bind.relationship,
          endpoints: resolved.bind.endpoints,
        }
      },
      presentCall: args => ({ card: 'generic', title: 'Bind conversation', kind: 'other', rawInput: args }),
    }))

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
          foldBind(context.agent.session.events),
          foldToolResultText(context.agent.session.events),
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
   * Latest live conversation bind on a session log.
   * @param session - session whose log is folded.
   * @returns the last bind, or undefined.
   */
  bind(session: Session): RelationshipBind | undefined {
    return foldBind(session.events)
  }

  /**
   * Append one identity when kind+value is new, or when a later harvest
   * supplies `evidence_id` that the first-seen row lacks, or when a later
   * MAC harvest stamps the bound victim or a C2-talking LAN IP over a
   * DC/peer first stamp.
   * Unique-on-kind+value still yields one folded row. A restamp does not
   * count as a new identity for hunt issuance. A later DC/peer stamp does
   * not overwrite a victim or C2-talking stamp.
   * @param session - session to append to.
   * @param identity - identity to record.
   * @returns true when a new kind+value was appended.
   */
  recordIdentity(session: Session, identity: Identity): boolean {
    const existing = foldIdentities(session.events).find(
      item => identityKey(item) === identityKey(identity),
    )
    if (existing === undefined) {
      session.append('investigation/identity', identity)
      return true
    }
    if (restampEvidenceId(existing, identity, preferredMacEvidenceIds(session.events)) !== undefined) {
      session.append('investigation/identity', identity)
    }
    return false
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
   * Append a whole-value conversation bind. The last bind is the live bind.
   * @param session - session to append to.
   * @param bind - resolved relationship and endpoints.
   */
  recordBind(session: Session, bind: RelationshipBind): void {
    session.append('investigation/bind', bind)
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
    const { added, issued } = await this.harvestIssueAutoRun(exec, exec.agent.session, resultText(result))
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
   * Harvest identities from `current`, issue identity hunts, and auto-run
   * outstanding issued hunts (including `other-end`).
   * @param exec - triggering execution (path and cancellation).
   * @param session - session whose ledger is folded.
   * @param current - text of the triggering tool result, or empty on a denied bind.
   * @returns identities and hunts recorded on this pass.
   */
  private async harvestIssueAutoRun(
    exec: ToolExecution,
    session: Session,
    current: string,
  ): Promise<{ added: Identity[]; issued: Hunt[] }> {
    const added: Identity[] = []
    const issued: Hunt[] = []
    const evidence = (): string => evidenceTextForHunts(session.events, current)
    const harvestFrom = (text: string, evidenceText: string, scopeIp?: string): void => {
      for (const identity of harvestIdentities(text, evidenceText, scopeIp)) {
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
    harvestFrom(current, evidence(), scopeIpFromPcapFilter(exec.arguments))
    issueFrom(added)
    if (this.autoHunt) {
      await this.autoRunOutstanding(exec, session, current, (text, hunt) => {
        const before = added.length
        harvestFrom(text, `${evidence()}\n${text}`, scopeIpFromHunt(hunt))
        issueFrom(added.slice(before))
      })
    }
    return { added, issued }
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
    onText: (text: string, hunt: Hunt) => void,
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
      if (text !== '') onText(text, hunt)
    }
  }
}

/**
 * Hunt-subject IPv4 for an `eth-src` or `name-service` dump.
 * @param hunt - issued hunt whose dump is being harvested.
 * @returns the IP subject, or undefined when the hunt is not IP-scoped.
 */
function scopeIpFromHunt(hunt: Hunt): string | undefined {
  if (hunt.subjectKind !== 'ip') return undefined
  if (hunt.kind === 'eth-src' || hunt.kind === 'name-service') return hunt.subject
  return undefined
}

/**
 * Hunt-subject IPv4 implied by a `pcap_filter` display filter.
 * `eth.src` with `ip.src ==` or `ip.addr ==` scopes a MAC dump; `llmnr` /
 * `nbns` / `browser` with `ip.addr ==` scopes a name-service dump.
 * @param args - tool arguments that may include `display_filter`.
 * @returns the scoped IPv4, or undefined when the filter is not those hunts.
 */
function scopeIpFromPcapFilter(args: unknown): string | undefined {
  const filter = stringArg(args, ['display_filter'])
  if (filter === undefined) return undefined
  const eth = /\beth\.src\b/.test(filter)
    ? /ip\.(?:src|addr)\s*==\s*(\d{1,3}(?:\.\d{1,3}){3})/.exec(filter)
    : null
  if (eth?.[1] !== undefined) return eth[1]
  if (!/\b(?:llmnr|nbns|browser)\b/.test(filter)) return undefined
  return /ip\.addr\s*==\s*(\d{1,3}(?:\.\d{1,3}){3})/.exec(filter)?.[1]
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

/** Model-facing bind_relationship description. */
const BIND_RELATIONSHIP_DESCRIPTION = [
  'Bind the cited conversation before Who/Where.',
  'Assign victim vs c2 (or infra, distractor, unknown) on each endpoint.',
  'The cited conversation must include a cue/observation address. Role c2 cannot be a LAN address.',
  'Cue and observation addresses default to c2 and cannot be victim.',
  'Exactly one victim.',
].join(' ')

/**
 * Whether tool arguments attempt to set who/where identity slots.
 * @param args - parsed tool arguments.
 * @returns true when who or where is present.
 */
export function setsWhoWhere(args: unknown): boolean {
  if (typeof args !== 'object' || args === null) return false
  return 'who' in args || 'where' in args
}
