/**
 * BindRelationship: assign victim vs c2 on a cited conversation before
 * Who/Where. Cue/observation addresses default to c2. A live bind is
 * required to close; who/where project from the victim entity row.
 * @module @deepseek-ai/dsh-investigation/bind
 */

import { normalizeIdentityValue } from './harvest.ts'
import { isNonLanUnicastIpv4 } from './hunts.ts'
import { c2TalkingLanVictim } from './report.ts'
import type {
  BoundEndpoint, CaseIdentitySlot, CaseReport, EndpointRole, Identity, Relationship,
  RelationshipBind,
} from './types.ts'

/** Closed role set accepted by bind_relationship. */
export const ENDPOINT_ROLES = ['victim', 'c2', 'infra', 'distractor', 'unknown'] as const

/** Deny text when case_report runs without a live victim-vs-c2 bind. */
export const UNBOUND_REASON = 'unbound: assign victim vs c2 on the cited conversation.'

/** Deny text when bind_relationship does not have exactly one victim. */
export const VICTIM_COUNT_REASON = 'bind_relationship requires exactly one victim'

const ROLE_SET = new Set<string>(ENDPOINT_ROLES)
const CONVERSATION_CUE = /\b(conversation|talking|packet|flow|peer|cited conversation)\b/i

/** Model or fold input before defaults and role checks. */
export interface BindRequest {
  /** Cited conversation. */
  relationship: Relationship
  /** Endpoints the model assigned. Missing src/dst are completed with defaults. */
  endpoints: readonly BindEndpointInput[]
}

/** One endpoint as submitted to bind_relationship. */
export interface BindEndpointInput {
  /** Endpoint address. */
  addr: string
  /** Role, or omitted so a cue/observation address defaults to `c2`. */
  role?: EndpointRole
  /** Why this role was assigned. */
  because: string
}

/** Claims case_report still accepts as free text. */
export interface CaseReportClaims {
  /** What happened. */
  what: string
  /** When it happened. */
  when: string
  /** Why it happened, as evidenced. */
  why: string
  /** How it happened, as evidenced. */
  how: string
}

/** Result of resolving a bind request. */
export type BindResolution =
  | { ok: true; bind: RelationshipBind }
  | { ok: false; reason: string }

/**
 * Normalize one endpoint address. IPv4 is lowercased like harvested IPs.
 * @param addr - raw address.
 * @returns trimmed canonical address, or undefined when empty.
 */
export function normalizeEndpointAddr(addr: string): string | undefined {
  const trimmed = addr.trim()
  if (trimmed === '') return undefined
  const ip = normalizeIdentityValue('ip', trimmed)
  return ip === undefined ? trimmed.toLowerCase() : ip
}

/**
 * Whether an address is a cue/observation (external / detector) IP.
 * Those addresses default to role `c2`.
 * @param addr - normalized address.
 * @returns true for a unicast non-LAN IPv4.
 */
export function isCueObservationAddr(addr: string): boolean {
  return isNonLanUnicastIpv4(addr)
}

/**
 * Default role for an address the model did not assign.
 * Cue/observation addresses become `c2`; every other address becomes `unknown`.
 * @param addr - normalized address.
 * @returns the default role.
 */
export function defaultRoleForAddr(addr: string): EndpointRole {
  return isCueObservationAddr(addr) ? 'c2' : 'unknown'
}

/**
 * Whether `because` cites the conversation rather than only the alert string.
 * A citation names `evidence_id`, both endpoints, the destination port, or a
 * conversation token (talking, packet, flow, peer).
 * @param because - role justification.
 * @param relationship - cited conversation.
 * @returns true when the text cites conversation evidence.
 */
export function citesConversation(because: string, relationship: Relationship): boolean {
  const text = because.toLowerCase()
  if (text.includes(relationship.evidence_id.toLowerCase())) return true
  const src = relationship.src.toLowerCase()
  const dst = relationship.dst.toLowerCase()
  if (src !== '' && dst !== '' && text.includes(src) && text.includes(dst)) return true
  if (text.includes(`:${relationship.dport}`) || /\b(?:d)?port\s+(\d+)\b/i.test(because)) {
    const port = /\b(?:d)?port\s+(\d+)\b/i.exec(because)?.[1]
    if (port === String(relationship.dport) || text.includes(`:${relationship.dport}`)) return true
  }
  return CONVERSATION_CUE.test(because)
}

/**
 * Fold the latest live bind from a log prefix.
 * @param events - session log or any prefix of it.
 * @returns the last bind, or undefined when none exists.
 */
export function foldBind(events: readonly { type: string; data: unknown }[]): RelationshipBind | undefined {
  let bind: RelationshipBind | undefined
  for (const event of events) {
    if (event.type === 'investigation/bind') bind = event.data as RelationshipBind
  }
  return bind
}

/**
 * The unique victim endpoint on a live bind.
 * @param bind - recorded bind.
 * @returns the victim endpoint, or undefined when the bind is not exactly-one-victim.
 */
export function victimOf(bind: RelationshipBind): BoundEndpoint | undefined {
  const victims = bind.endpoints.filter(endpoint => endpoint.role === 'victim')
  return victims.length === 1 ? victims[0] : undefined
}

/**
 * Resolve and validate a BindRelationship request.
 * Missing src/dst endpoints are completed with default roles. Cue/observation
 * addresses default to `c2`. Assigning `victim` to a cue address requires a
 * `because` that cites the conversation. Zero or two victims fail.
 * @param request - relationship plus submitted endpoints.
 * @returns the bind, or a deny reason.
 */
export function resolveBind(request: BindRequest): BindResolution {
  const relationship = normalizeRelationship(request.relationship)
  if (typeof relationship === 'string') return { ok: false, reason: relationship }

  const seen = new Set<string>()
  const endpoints: BoundEndpoint[] = []
  for (const input of request.endpoints) {
    const resolved = resolveEndpoint(input, relationship, seen)
    if (typeof resolved === 'string') return { ok: false, reason: resolved }
    endpoints.push(resolved)
  }
  for (const addr of [relationship.src, relationship.dst]) {
    if (seen.has(addr)) continue
    seen.add(addr)
    endpoints.push({
      addr,
      role: defaultRoleForAddr(addr),
      because: isCueObservationAddr(addr) ? 'cue/observation address' : 'unassigned endpoint',
    })
  }
  const victims = endpoints.filter(endpoint => endpoint.role === 'victim')
  if (victims.length !== 1) return { ok: false, reason: VICTIM_COUNT_REASON }
  return { ok: true, bind: { relationship, endpoints } }
}

/**
 * Entity id an identity may donate for. IPs donate as themselves. An explicit
 * `entity_id` wins. A MAC sourced from the C2-talking LAN IP donates to that IP
 * when it matches the bound victim. Distractors never donate.
 * @param identity - ledger identity.
 * @param bind - live bind.
 * @param identities - full ledger, used to resolve a sourced MAC.
 * @param evidenceText - tool-result text for C2-talking detection.
 * @returns the entity id, or undefined when the identity is unaffiliated.
 */
export function entityIdForIdentity(
  identity: Identity,
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText = '',
): string | undefined {
  if (identity.entity_id !== undefined && identity.entity_id !== '') return identity.entity_id
  if (identity.kind === 'ip') return identity.value
  if (identity.kind === 'mac') {
    const sourced = c2TalkingLanVictim(identities, evidenceText)
    const victim = victimOf(bind)
    if (
      sourced !== undefined
      && sourced.mac === identity.value
      && victim !== undefined
      && sourced.ip === victim.addr
    ) {
      return victim.addr
    }
  }
  return undefined
}

/**
 * Whether an identity may donate a who/where slot for the bound victim.
 * Distractors and other non-victim entities cannot donate. An `evidence_id`
 * that names a non-victim entity also blocks donation.
 * @param identity - ledger identity.
 * @param bind - live bind.
 * @param identities - full ledger.
 * @param evidenceText - tool-result text for C2-talking detection.
 * @returns true when the identity belongs to the unique victim.
 */
export function identityDonatesToVictim(
  identity: Identity,
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText = '',
): boolean {
  const victim = victimOf(bind)
  if (victim === undefined) return false
  if (pointsAtNonVictim(identity.evidence_id, bind)) return false
  return entityIdForIdentity(identity, bind, identities, evidenceText) === victim.addr
}

/**
 * Project the victim entity row (IP / MAC / hostname / user).
 * @param bind - live bind with exactly one victim.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text for sourced-MAC affiliation.
 * @returns the projected slot, or undefined when the bind has no unique victim.
 */
export function projectVictimSlot(
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText = '',
): CaseIdentitySlot | undefined {
  const victim = victimOf(bind)
  if (victim === undefined) return undefined
  const slot: CaseIdentitySlot = { entity_id: victim.addr }
  const donated = identities.filter(identity => (
    identityDonatesToVictim(identity, bind, identities, evidenceText)
  ))
  const first = (kind: Identity['kind']): string | undefined => (
    donated.find(identity => identity.kind === kind)?.value
  )
  const ip = first('ip') ?? (isIpv4(victim.addr) ? victim.addr : undefined)
  if (ip !== undefined) slot.ip = ip
  const mac = first('mac')
  if (mac !== undefined) slot.mac = mac
  const hostname = first('hostname')
  if (hostname !== undefined) slot.hostname = hostname
  const user = first('user')
  if (user !== undefined) slot.user = user
  return slot
}

/**
 * Build the persisted case_report packet. who/where are the victim row.
 * @param bind - live bind.
 * @param identities - folded ledger identities.
 * @param claims - what / when / why / how.
 * @param evidenceText - tool-result text for sourced-MAC affiliation.
 * @returns the report, or undefined when the bind has no unique victim.
 */
export function projectCaseReport(
  bind: RelationshipBind,
  identities: readonly Identity[],
  claims: CaseReportClaims,
  evidenceText = '',
): CaseReport | undefined {
  const slot = projectVictimSlot(bind, identities, evidenceText)
  if (slot === undefined) return undefined
  return {
    who: slot,
    what: claims.what,
    when: claims.when,
    where: slot,
    why: claims.why,
    how: claims.how,
  }
}

/**
 * Deny reason for case_report or an attempt to set who/where.
 * Missing bind, inverted entity_id, free-text who/where, and identity slots
 * whose evidence_id points at a non-victim all return {@link UNBOUND_REASON}.
 * @param args - tool arguments.
 * @param bind - live bind, or undefined when unbound.
 * @param identities - folded ledger identities.
 * @returns the deny reason, or undefined when the close may proceed.
 */
export function caseReportDenyReason(
  args: unknown,
  bind: RelationshipBind | undefined,
  identities: readonly Identity[] = [],
): string | undefined {
  const victim = bind === undefined ? undefined : victimOf(bind)
  if (bind === undefined || victim === undefined) return UNBOUND_REASON
  if (typeof args !== 'object' || args === null) return undefined
  const record = args as Record<string, unknown>
  for (const field of ['who', 'where'] as const) {
    const value = record[field]
    if (value === undefined) continue
    if (typeof value === 'string') return UNBOUND_REASON
    if (typeof value !== 'object' || value === null) return UNBOUND_REASON
    const slot = value as { entity_id?: unknown; evidence_id?: unknown }
    if (slot.entity_id !== undefined) {
      if (typeof slot.entity_id !== 'string') return UNBOUND_REASON
      const entityId = normalizeEndpointAddr(slot.entity_id)
      if (entityId !== victim.addr) return UNBOUND_REASON
    }
    if (typeof slot.evidence_id === 'string' && pointsAtNonVictim(slot.evidence_id, bind, identities)) {
      return UNBOUND_REASON
    }
  }
  return undefined
}

/**
 * Render the focus/roles card for the prompt ledger and bind_relationship result.
 * @param bind - live bind.
 * @returns card text.
 */
export function formatRolesCard(bind: RelationshipBind): string {
  const { relationship } = bind
  const lines = [
    'Conversation bind',
    `${relationship.src} → ${relationship.dst} :${relationship.dport} @ ${relationship.t}`,
    `evidence ${relationship.evidence_id}`,
  ]
  const order = (role: EndpointRole): number => {
    if (role === 'victim') return 0
    if (role === 'c2') return 1
    if (role === 'infra') return 2
    if (role === 'distractor') return 3
    return 4
  }
  const endpoints = [...bind.endpoints].sort((left, right) => order(left.role) - order(right.role))
  for (const endpoint of endpoints) {
    lines.push(`- ${endpoint.role} ${endpoint.addr} because ${endpoint.because}`)
  }
  return lines.join('\n')
}

/**
 * Role label for one identity on the ledger card, when a live bind exists.
 * @param identity - ledger identity.
 * @param bind - live bind.
 * @param identities - full ledger.
 * @param evidenceText - tool-result text for sourced-MAC affiliation.
 * @returns the role, or undefined when the identity is unaffiliated.
 */
export function roleForIdentity(
  identity: Identity,
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText = '',
): EndpointRole | undefined {
  const entityId = entityIdForIdentity(identity, bind, identities, evidenceText)
  if (entityId === undefined) return undefined
  return bind.endpoints.find(endpoint => endpoint.addr === entityId)?.role
}

function normalizeRelationship(raw: Relationship): Relationship | string {
  const src = normalizeEndpointAddr(raw.src)
  const dst = normalizeEndpointAddr(raw.dst)
  const evidenceId = raw.evidence_id.trim()
  const time = raw.t.trim()
  if (src === undefined || dst === undefined) {
    return 'bind_relationship relationship src and dst must be non-empty'
  }
  if (evidenceId === '') return 'bind_relationship relationship evidence_id must be a non-empty string'
  if (time === '') return 'bind_relationship relationship t must be a non-empty string'
  if (!Number.isInteger(raw.dport) || raw.dport < 1 || raw.dport > 65535) {
    return 'bind_relationship relationship dport must be an integer 1-65535'
  }
  return { src, dst, dport: raw.dport, t: time, evidence_id: evidenceId }
}

function resolveEndpoint(
  input: BindEndpointInput,
  relationship: Relationship,
  seen: Set<string>,
): BoundEndpoint | string {
  const addr = normalizeEndpointAddr(input.addr)
  if (addr === undefined) return 'bind_relationship endpoint addr must be a non-empty string'
  if (seen.has(addr)) return `bind_relationship endpoint ${addr} is duplicated`
  const because = input.because.trim()
  if (because === '') return 'bind_relationship endpoint because must be a non-empty string'
  const role = input.role ?? defaultRoleForAddr(addr)
  if (!ROLE_SET.has(role)) return `bind_relationship endpoint role ${JSON.stringify(input.role)} is not valid`
  if (role === 'victim' && isCueObservationAddr(addr) && !citesConversation(because, relationship)) {
    return UNBOUND_REASON
  }
  seen.add(addr)
  return { addr, role, because }
}

function pointsAtNonVictim(
  evidenceId: string | undefined,
  bind: RelationshipBind,
  identities: readonly Identity[] = [],
): boolean {
  if (evidenceId === undefined || evidenceId === '') return false
  const victim = victimOf(bind)
  if (victim === undefined) return true
  if (evidenceId === bind.relationship.evidence_id) return false
  const named = bind.endpoints.find(endpoint => endpoint.addr === evidenceId)
  if (named !== undefined) return named.role !== 'victim'
  return identities.some(identity => (
    identity.evidence_id === evidenceId
    && identity.entity_id !== undefined
    && identity.entity_id !== victim.addr
  ))
}

function isIpv4(addr: string): boolean {
  return /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(addr)
}
