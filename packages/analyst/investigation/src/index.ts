/**
 * Case-scoped investigation ledger: harvest unique labeled identities from
 * tool results, persist Mission / Plan / Action / Report around DINQ
 * (Observation → Question → Hypothesis → Answer → Bind → Who/Where),
 * auto-issue hunts after new identities, auto-issue `other-end`
 * when bind_relationship assigns a cue as victim, auto-issue `extra-wan`
 * then `c2-domain` on a successful bind with a unique LAN victim and
 * unique non-LAN C2 that is not a well-known CDN or update destination
 * after Plan is ready, auto-run outstanding
 * issued hunts through `pcap_filter`, deny writes to evidence and work
 * outside the case directory, require BindRelationship before case_report,
 * deny write/edit of case-root close files, persist leftover extras from
 * the Report hook even when prose case_report stays unbound, and persist a
 * 5W1H close packet whose who/where project from the bound victim entity row.
 * Mission does not unlock auto-hunts.
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
  caseReportDenyReason, c2DomainHuntForBind, c2DomainHuntsForBind, ENDPOINT_ROLES,
  extraWanHuntForBind, foldBind, formatRolesCard, otherEndHuntForDeniedBind, resolveBind,
  victimOf, boundC2Ipv4,
} from './bind.ts'
import { harvestIdentities, identityKey } from './harvest.ts'
import {
  c2TalkingLanIps, evidenceTextForHunts, foldToolResultText, huntFilterSpec, huntNotice,
  huntsForNewIdentities, huntsToAutoRun, huntKey, isNonLanUnicastIpv4,
} from './hunts.ts'
import { formatLedger } from './ledger.ts'
import {
  actionForHunt, applyHuntExtras, foldActions, foldExtras, foldMission, foldPlan,
  killedHypothesisIds, planEntryDenyReason, planReady, planReadyDenyReason, projectHuntExtras,
  requireC2HypothesisId, sameHuntExtras, thesisForHuntDump,
} from './mindset.ts'
import { denyReason, stringArg } from './policy.ts'
import { isEvidencePath, isInsideCase, isWritablePath, resolveInsideCase } from './paths.ts'
import { isCdnOrUpdateName } from './harvest.ts'
import type {
  CaseReport, CaseReportExtras, Hunt, Identity, InvestigationAction, InvestigationMission,
  InvestigationPlanEntry, RelationshipBind,
} from './types.ts'

export type * from './types.ts'
export type { HuntFilterSpec } from './hunts.ts'
export {
  decodeUtf16LeHex, harvestIdentities, hostnamesEvidencedOnIp, identityKey, identityOf,
  IDENTITY_LABELS, isC2DomainName, isCdnOrUpdateName, normalizeIdentityValue,
} from './harvest.ts'
export {
  c2DomainDisplayFilter, c2DomainHunt, c2TalkingLanIps, displayFilterFor, evidenceTextForHunts,
  extraWanDisplayFilter, extraWanHunt, foldToolResultText, huntFilterSpec, huntKey, huntNotice,
  huntsForNewIdentities, huntsToAutoRun, isLanIpv4, isNonLanUnicastIpv4, otherEndDisplayFilter,
  otherEndHunt, shouldAutoRunHunt,
} from './hunts.ts'
export { formatLedger } from './ledger.ts'
export {
  actionForHunt, applyHuntExtras, c2HypothesisId, foldActions, foldExtras, foldMission, foldPlan,
  isBelieveBecauseClaim, killedHypothesisIds, planEntryDenyReason, planReady, planReadyDenyReason,
  PLAN_NOT_READY_REASON, projectHuntExtras, requireC2HypothesisId, sameHuntExtras, thesisForHuntDump,
} from './mindset.ts'
export { c2TalkingLanVictim } from './report.ts'
export type { C2TalkingLanVictim } from './report.ts'
export {
  BOTH_LAN_CONVERSATION_REASON, caseReportDenyReason, coerceBindRequest, completeAcceptedSlot,
  cueVictimUnboundReason, defaultRoleForAddr, ENDPOINT_ROLES, ENDPOINTS_ARRAY_REASON,
  entityIdForIdentity, foldBind, formatRolesCard, identityDonatesToVictim, isCueObservationAddr,
  CDN_C2_REASON, LAN_C2_REASON, normalizeEndpointAddr, otherEndHuntForDeniedBind,
  projectCaseReport, projectVictimSlot, requireCaseReport, resolveBind, roleForIdentity,
  UNBOUND_REASON, victimOf, VICTIM_COUNT_REASON, acceptedC2Domain, acceptedC2Ips, boundC2Ipv4,
  c2DomainHuntForBind, c2DomainHuntsForBind, extraWanHuntForBind,
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
  'Mission, Plan, Action, and Report wrap Observation, then Question, then Hypothesis, then Answer, then Bind, then Who/Where.',
  'Do not skip Observation or Question or Hypothesis. Mission scopes the case and validates the cue; it does not unlock hunts.',
  'Plan names each hypothesis as I believe X because Y plus a disconfirm test, including a C2 hypothesis and a CDN, DC, or update alternative.',
  'Before Who/Where, bind the conversation. The detector’s IP is a hypothesis about the other end until the bind says otherwise.',
  'Use bind_relationship to assign victim vs c2 on the cited conversation. Exactly one victim. The cited conversation must include a cue/observation address. Role c2 cannot be a LAN address or a well-known CDN or update destination. Cue and observation addresses default to c2 and cannot be victim.',
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
   * bind issues `other-end` for that cue. A successful bind with a unique LAN
   * victim and unique non-LAN C2 that is not a well-known CDN or update
   * destination issues `extra-wan` for that victim and
   * `c2-domain` for each remaining C2 IPv4 (bound plus harvested extras)
   * only when Plan is ready (cue valid or open, a C2 hypothesis, a
   * CDN/DC/update alternative, and an inventory). Outstanding
   * issued hunts then run through `pcap_filter` with the scoped
   * display_filter and fields; results harvest into the ledger. Non-LAN /
   * C2 IP subjects do not auto-run, except `other-end` and `c2-domain`.
   * `extra-wan` auto-runs for the LAN victim even when a C2-talking focus
   * IP exists. Mission does not unlock those leftover hunts. Defaults to true.
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
 * Overlays leftover extras from the Report hook. Extras-only persist
 * without a 5W1H packet is not a close: this returns undefined then.
 * @param events - session log or any prefix of it.
 * @returns the last report with extras applied, or undefined when none exists.
 */
export function foldReport(events: readonly SessionEvent[]): CaseReport | undefined {
  let report: CaseReport | undefined
  for (const event of events) {
    if (event.type === 'investigation/report') report = event.data
  }
  if (report === undefined) return undefined
  return applyHuntExtras(report, foldExtras(events))
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
                    description: 'Why this role. A cue/observation address cannot be victim. Role c2 cannot be a LAN address or a well-known CDN or update destination.',
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
        const identities = foldIdentities(exec.agent.session.events)
        const evidenceText = foldToolResultText(exec.agent.session.events)
        const resolved = resolveBind(request, identities, evidenceText)
        if (!resolved.ok) {
          const hunt = otherEndHuntForDeniedBind(request)
          if (hunt !== undefined) {
            this.recordHunt(exec.agent.session, hunt)
            if (this.autoHunt) await this.harvestIssueAutoRun(exec, exec.agent.session, '')
          }
          throw new Error(resolved.reason)
        }
        const planDeny = planReadyDenyReason(
          foldMission(exec.agent.session.events),
          foldPlan(exec.agent.session.events),
        )
        if (planDeny !== undefined) throw new Error(planDeny)
        this.recordBind(exec.agent.session, resolved.bind)
        let issued = false
        const extraWan = extraWanHuntForBind(resolved.bind)
        if (extraWan !== undefined) {
          this.recordHunt(exec.agent.session, extraWan)
          issued = true
        }
        const hunt = c2DomainHuntForBind(resolved.bind)
        if (hunt !== undefined) {
          this.recordHunt(exec.agent.session, hunt)
          issued = true
        }
        if (issued && this.autoHunt) await this.harvestIssueAutoRun(exec, exec.agent.session, '')
        return {
          ...resolved.bind.relationship,
          endpoints: resolved.bind.endpoints,
        }
      },
      presentCall: args => ({ card: 'generic', title: 'Bind conversation', kind: 'other', rawInput: args }),
    }))

    ctx.tools.register(defineTool({
      name: 'investigation_mission',
      description: [
        'Persist the Mission: purpose, cue pointer, slot 0a validate-the-cue, scored slots, and closed-means.',
        'Mission scopes the case. It does not unlock auto-hunts and does not skip Observation then Question then Hypothesis.',
      ].join(' '),
      parameters: {
        purpose: { type: 'string', required: true, description: 'Why this case is being investigated.' },
        cue_addr: { type: 'string', required: true, description: 'Cue or observation address.' },
        cue_evidence_id: { type: 'string', required: true, description: 'Id of the cited cue evidence.' },
        cue_validation: {
          type: 'string',
          required: true,
          enum: ['valid', 'open', 'invalid'],
          description: 'Slot 0a: whether this observation is valid, still open, or invalid.',
        },
        closed_means: {
          type: 'array',
          items: { type: 'string' },
          description: 'Closed investigative means. identity+c2 scopes an Easy-as-123 case; no origin or family hunt.',
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            purpose: { type: 'string', required: true },
            cue_addr: { type: 'string', required: true },
            cue_evidence_id: { type: 'string', required: true },
            cue_validation: { type: 'string', required: true },
          },
        },
        render: (_args, value) => [{
          type: 'text',
          text: `Mission recorded: ${value.purpose} (cue ${value.cue_validation}).`,
        }],
      },
      execute: (args, exec) => {
        if (exec.agent === undefined) throw new Error('investigation_mission requires an owning agent session')
        const purpose = args.purpose.trim()
        const cueAddr = args.cue_addr.trim()
        const cueEvidence = args.cue_evidence_id.trim()
        if (purpose === '' || cueAddr === '' || cueEvidence === '') {
          throw new Error('investigation_mission purpose, cue_addr, and cue_evidence_id must be non-empty')
        }
        const mission: InvestigationMission = {
          purpose,
          slots: { '0a': { value: args.cue_validation } },
          closedMeans: (args.closed_means ?? []).map(item => item.trim()).filter(item => item !== ''),
          cue: { addr: cueAddr, evidence_id: cueEvidence },
          cueValidation: args.cue_validation,
        }
        this.recordMission(exec.agent.session, mission)
        return Promise.resolve({
          purpose: mission.purpose,
          cue_addr: mission.cue.addr,
          cue_evidence_id: mission.cue.evidence_id,
          cue_validation: mission.cueValidation,
        })
      },
      presentCall: args => ({ card: 'generic', title: 'Mission', kind: 'other', rawInput: args }),
    }))

    ctx.tools.register(defineTool({
      name: 'investigation_plan',
      description: [
        'Append to the live Plan: source inventory, gaps, and hypotheses.',
        'Each hypothesis is I believe X because Y plus a disconfirm test.',
        'Candidate labels are victim, c2, dc, cdn, update, distractor.',
        'Answers generate more questions. This call appends; it does not replace.',
      ].join(' '),
      parameters: {
        inventory: {
          type: 'array',
          items: { type: 'string' },
          description: 'Sources that can attest.',
        },
        gaps: {
          type: 'array',
          items: { type: 'string' },
          description: 'Known gaps.',
        },
        hypotheses: {
          type: 'array',
          items: {
            type: 'object',
            additionalProperties: false,
            properties: {
              id: { type: 'string', required: true, description: 'Hypothesis id. Action rows cite this id.' },
              claim: {
                type: 'string',
                required: true,
                description: 'I believe X because Y.',
              },
              disconfirm: { type: 'string', required: true, description: 'How this hypothesis would be killed.' },
              label: {
                type: 'string',
                required: true,
                enum: ['victim', 'c2', 'dc', 'cdn', 'update', 'distractor'],
                description: 'Candidate role label.',
              },
            },
          },
          description: 'Hypotheses to append.',
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            inventory: { type: 'integer', required: true },
            gaps: { type: 'integer', required: true },
            hypotheses: { type: 'integer', required: true },
          },
        },
        render: (_args, value) => [{
          type: 'text',
          text: `Plan appended: ${value.hypotheses} hypotheses, ${value.inventory} inventory, ${value.gaps} gaps.`,
        }],
      },
      execute: (args, exec) => {
        if (exec.agent === undefined) throw new Error('investigation_plan requires an owning agent session')
        const entry: InvestigationPlanEntry = {}
        const inventory = (args.inventory ?? []).map(item => item.trim()).filter(item => item !== '')
        const gaps = (args.gaps ?? []).map(item => item.trim()).filter(item => item !== '')
        if (inventory.length > 0) entry.inventory = inventory
        if (gaps.length > 0) entry.gaps = gaps
        if (args.hypotheses !== undefined && args.hypotheses.length > 0) {
          entry.hypotheses = args.hypotheses.map(item => ({
            id: item.id.trim(),
            claim: item.claim.trim(),
            disconfirm: item.disconfirm.trim(),
            label: item.label,
          }))
        }
        const denied = planEntryDenyReason(entry)
        if (denied !== undefined) throw new Error(denied)
        this.recordPlan(exec.agent.session, entry)
        const plan = foldPlan(exec.agent.session.events)
        return Promise.resolve({
          inventory: plan.inventory.length,
          gaps: plan.gaps.length,
          hypotheses: plan.hypotheses.length,
        })
      },
      presentCall: args => ({ card: 'generic', title: 'Plan', kind: 'other', rawInput: args }),
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
          foldMission(context.agent.session.events),
          foldPlan(context.agent.session.events),
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
   * Append a whole-value 5W1H close packet. Re-merges leftover extras from
   * the Report hook so a later accepted close keeps them.
   * @param session - session to append to.
   * @param report - 5W1H fields.
   */
  recordReport(session: Session, report: CaseReport): void {
    session.append('investigation/report', applyHuntExtras(report, foldExtras(session.events)))
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
   * Append a whole-value Mission. The last Mission is live. Does not issue
   * or auto-run hunts.
   * @param session - session to append to.
   * @param mission - Mission fields.
   */
  recordMission(session: Session, mission: InvestigationMission): void {
    session.append('investigation/mission', mission)
  }

  /**
   * Append one Plan entry. Inventory, gaps, and new hypothesis ids concatenate.
   * Does not issue or auto-run hunts.
   * @param session - session to append to.
   * @param entry - Plan entry to append.
   */
  recordPlan(session: Session, entry: InvestigationPlanEntry): void {
    session.append('investigation/plan', entry)
  }

  /**
   * Append one Action hunt outcome.
   * @param session - session to append to.
   * @param action - Action row.
   */
  recordAction(session: Session, action: InvestigationAction): void {
    session.append('investigation/action', action)
  }

  /**
   * Latest Mission on a session log.
   * @param session - session whose log is folded.
   * @returns the last Mission, or undefined.
   */
  mission(session: Session): InvestigationMission | undefined {
    return foldMission(session.events)
  }

  /**
   * Leftover extras from the Report hook. Not an accepted close.
   * @param session - session whose log is folded.
   * @returns extras, or undefined when none exist.
   */
  extras(session: Session): CaseReportExtras | undefined {
    return foldExtras(session.events)
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
   * outstanding issued hunts (including `other-end`, `extra-wan`, and `c2-domain`).
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
        if (hunt.kind === 'extra-wan' || hunt.kind === 'c2-domain') {
          this.recordHuntAction(session, hunt, added.slice(before))
        }
        if (hunt.kind === 'extra-wan') {
          const bind = foldBind(session.events)
          if (bind !== undefined) {
            for (const next of c2DomainHuntsForBind(
              bind,
              foldIdentities(session.events),
              evidence(),
            )) {
              if (this.recordHunt(session, next)) issued.push(next)
            }
          }
          return
        }
        if (hunt.kind !== 'c2-domain') issueFrom(added.slice(before))
      })
    }
    this.persistReportExtras(session)
    return { added, issued }
  }

  /**
   * Report hook: persist leftover extras from proven extra-wan / c2-domain
   * hunts. Not an accepted close. Who/where are not invented. A later
   * accepted case_report re-merges these extras.
   * @param session - session whose bind, identities, and Actions are folded.
   */
  private persistReportExtras(session: Session): void {
    const bind = foldBind(session.events)
    if (bind === undefined) return
    const extras = projectHuntExtras(
      bind,
      foldIdentities(session.events),
      foldToolResultText(session.events),
      killedHypothesisIds(foldActions(session.events)),
    )
    if (extras === undefined) return
    if (sameHuntExtras(foldExtras(session.events), extras)) return
    session.append('investigation/extras', extras)
    const existing = lastAcceptedReport(session.events)
    if (existing !== undefined) {
      session.append('investigation/report', applyHuntExtras(existing, extras))
    }
  }

  /**
   * Record one Action row for an extra-wan or c2-domain dump.
   * @param session - session to append to.
   * @param hunt - hunt that just ran.
   * @param harvested - identities harvested from that dump.
   */
  private recordHuntAction(session: Session, hunt: Hunt, harvested: readonly Identity[]): void {
    const hypothesisId = requireC2HypothesisId(foldPlan(session.events))
    let confirm = false
    let killed = false
    for (const identity of harvested) {
      if (hunt.kind === 'extra-wan' && identity.kind === 'ip' && isNonLanUnicastIpv4(identity.value)) {
        confirm = true
      }
      if (hunt.kind === 'c2-domain' && identity.kind === 'hostname') {
        if (isCdnOrUpdateName(identity.value)) killed = true
        else confirm = true
      }
    }
    if (confirm) killed = false
    this.recordAction(session, actionForHunt(
      hunt,
      hypothesisId,
      thesisForHuntDump(hunt.kind, confirm, killed),
      hunt.subject,
    ))
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
      const extrasReady = planReady(foldMission(session.events), foldPlan(session.events))
      const hunt = huntsToAutoRun(
        foldHunts(session.events),
        evidenceTextForHunts(session.events, current),
        executed,
        extrasReady,
      )[0]
      if (hunt === undefined) break
      executed.add(huntKey(hunt))
      const live = foldBind(session.events)
      const spec = huntFilterSpec(hunt, live === undefined ? undefined : boundC2Ipv4(live))
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
 * Hunt-subject IPv4 for an `eth-src`, `name-service`, `c2-domain`, or
 * `extra-wan` dump. Extra-wan scopes the bound victim so harvested dest
 * IPs stamp that victim as `evidence_id`.
 * @param hunt - issued hunt whose dump is being harvested.
 * @returns the IP subject, or undefined when the hunt is not IP-scoped.
 */
function scopeIpFromHunt(hunt: Hunt): string | undefined {
  if (hunt.subjectKind !== 'ip') return undefined
  if (
    hunt.kind === 'eth-src'
    || hunt.kind === 'name-service'
    || hunt.kind === 'c2-domain'
    || hunt.kind === 'extra-wan'
  ) {
    return hunt.subject
  }
  return undefined
}

/**
 * Hunt-subject IPv4 implied by a `pcap_filter` display filter.
 * `eth.src` with `ip.src ==` or `ip.addr ==` scopes a MAC dump; `llmnr` /
 * `nbns` / `browser` with `ip.addr ==` scopes a name-service dump.
 * TLS SNI or DNS fields with `ip.addr ==` or `ip.dst ==` scope a C2-domain dump.
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
  const domain = /\b(?:tls\.handshake\.extensions_server_name|dns\.(?:qry|resp)\.name)\b/.test(filter)
    ? /ip\.(?:addr|dst)\s*==\s*(\d{1,3}(?:\.\d{1,3}){3})/.exec(filter)
    : null
  if (domain?.[1] !== undefined) return domain[1]
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
  'The cited conversation must include a cue/observation address. Role c2 cannot be a LAN address or a well-known CDN or update destination.',
  'Cue and observation addresses default to c2 and cannot be victim.',
  'Exactly one victim.',
  'Name a C2 hypothesis and check CDN/DC/update alternatives on the Plan before this bind.',
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

/**
 * Last accepted 5W1H packet, without overlaying extras.
 * @param events - session log or any prefix of it.
 * @returns the last report payload, or undefined.
 */
function lastAcceptedReport(events: readonly SessionEvent[]): CaseReport | undefined {
  let report: CaseReport | undefined
  for (const event of events) {
    if (event.type === 'investigation/report') report = event.data
  }
  return report
}
