/**
 * BindRelationship: assign victim vs c2 on a cited conversation before
 * Who/Where. The conversation must include a cue/observation address.
 * Cue/observation addresses default to c2. Role c2 cannot be a LAN address.
 * A live bind is required to close; who/where project from the victim entity row.
 * After deny/coerce, omitted model keys are filled from that projected row.
 * After a live bind, a who/where string whose leftover identity tokens are
 * victim-row handles is coerced to `{ entity_id: victim }` even when labels
 * or a sentence wrap those handles. Locator leftovers (client / ip /
 * located / at / on / network) are wrappers. A leftover CIDR that contains
 * the bound victim IP is dropped so `/` does not shatter it into a
 * non-victim IPv4 plus a prefix. A leftover MAC that talking-IP frames
 * source only from a non-victim is dropped so remaining victim-row handles
 * still coerce. Omitted mac persists the unique ledger MAC that is not
 * DC/gateway-only when a sticky DC donate or uniqueness left the projected
 * row empty. Omitted user still persists from victim-IP evidence. A
 * submitted user, hostname, or full_name is kept when the row has no
 * donated value and that identity does not donate to a different entity. A
 * submitted mac is kept unless talking-IP frames source that MAC only from
 * a non-victim.
 * @module @deepseek-ai/dsh-investigation/bind
 */

import { ipsEvidencingIdentity, isC2DomainName, normalizeIdentityValue } from './harvest.ts'
import { c2DomainHunt, isLanIpv4, isNonLanUnicastIpv4, otherEndDisplayFilter, otherEndHunt } from './hunts.ts'
import { c2TalkingLanVictim } from './report.ts'
import type {
  BoundEndpoint, CaseIdentitySlot, CaseReport, EndpointRole, Hunt, Identity, IdentityKind,
  Relationship, RelationshipBind,
} from './types.ts'

/** Closed role set accepted by bind_relationship. */
export const ENDPOINT_ROLES = ['victim', 'c2', 'infra', 'distractor', 'unknown'] as const

/** Deny text when case_report runs without a live victim-vs-c2 bind. */
export const UNBOUND_REASON = 'unbound: assign victim vs c2 on the cited conversation.'

/**
 * Deny text when bind_relationship assigns victim to a cue/observation address.
 * Names the other-end hunt and filter. Does not invent a LAN peer.
 * @param cue - normalized cue/observation IPv4.
 * @returns unbound reason naming `other-end` for that cue.
 */
export function cueVictimUnboundReason(cue: string): string {
  return `unbound: hunt LAN ip.src talking to ${cue} (${otherEndDisplayFilter(cue)}).`
}

/**
 * Other-end hunt for a denied cue-as-victim bind, when one was submitted
 * on a conversation that includes a cue/observation address. A both-LAN
 * conversation deny does not issue this hunt and does not invent a C2.
 * @param request - the bind request that failed.
 * @returns the hunt for the first cue assigned victim, or undefined.
 */
export function otherEndHuntForDeniedBind(request: BindRequest): Hunt | undefined {
  const coerced = coerceBindRequest(request)
  if (typeof coerced === 'string') return undefined
  const relationship = normalizeRelationship(coerced.relationship)
  if (typeof relationship === 'string') return undefined
  if (!conversationIncludesCue(relationship.src, relationship.dst)) return undefined
  for (const input of coerced.endpoints) {
    const addr = normalizeEndpointAddr(input.addr)
    if (addr !== undefined && input.role === 'victim' && isCueObservationAddr(addr)) {
      return otherEndHunt(addr)
    }
  }
  return undefined
}

/**
 * C2-domain hunt for a live bind whose unique `c2` endpoint is a non-LAN
 * IPv4. A both-LAN deny never reaches a live bind, so this hunt is not
 * issued for a LAN C2.
 * @param bind - accepted conversation bind.
 * @returns the hunt for that C2 IPv4, or undefined when none is unique.
 */
export function c2DomainHuntForBind(bind: RelationshipBind): Hunt | undefined {
  const c2 = boundC2Ipv4(bind)
  return c2 === undefined ? undefined : c2DomainHunt(c2)
}

/**
 * Harvested TLS SNI or DNS name evidenced on the bound C2 IPv4.
 * LAN / DC / gateway / victim hostnames stay off. The name is not invented
 * and does not donate who/where.
 * @param bind - live bind.
 * @param identities - folded ledger identities.
 * @returns the first C2-stamped DNS name, or undefined when none exists.
 */
export function acceptedC2Domain(
  bind: RelationshipBind,
  identities: readonly Identity[],
): string | undefined {
  const c2 = boundC2Ipv4(bind)
  if (c2 === undefined) return undefined
  for (const identity of identities) {
    if (identity.kind !== 'hostname' || identity.evidence_id !== c2) continue
    if (isC2DomainName(identity.value)) return identity.value
  }
  return undefined
}

/** Deny text when bind_relationship does not have exactly one victim. */
export const VICTIM_COUNT_REASON = 'bind_relationship requires exactly one victim'

/** Deny text when endpoints is not an array after JSON-string coerce. */
export const ENDPOINTS_ARRAY_REASON = 'bind_relationship endpoints must be an array'

/**
 * Deny text when the cited conversation has no cue/observation address.
 * A workstation↔DC Kerberos/SAMR/LDAP flow is unbound. Does not invent a C2.
 */
export const BOTH_LAN_CONVERSATION_REASON =
  'unbound: cite the LAN host talking to the cue/observation address, not a LAN DC/AD service.'

/** Deny text when bind_relationship assigns c2 to a LAN address. Tokens are not swapped. */
export const LAN_C2_REASON = 'unbound: role c2 cannot be a LAN address.'

const ROLE_SET = new Set<string>(ENDPOINT_ROLES)
const HANDLE_KINDS = ['ip', 'mac', 'hostname', 'user', 'full_name'] as const satisfies readonly IdentityKind[]
const SLOT_KEYS = ['ip', 'mac', 'hostname', 'user', 'full_name'] as const satisfies readonly IdentityKind[]
const INTEGER_STRING = /^-?\d+$/
const MAC_HANDLE = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i
const IPV4_DOTTED = String.raw`(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)`
const IPV4_EXACT = new RegExp(`^${IPV4_DOTTED}$`)
const CIDR_PREFIX = String.raw`(?:3[0-2]|[12]?\d)`
const CIDR_EXACT = new RegExp(`^(${IPV4_DOTTED})/(${CIDR_PREFIX})$`)
/**
 * Field labels, locator words, and sentence wrappers that are not identity
 * tokens. A leftover word outside this set still denies when it is not a
 * handle, except a leftover MAC that talking-IP frames source only from a
 * non-victim, and a leftover CIDR that contains the bound victim IP.
 */
const HANDLE_WRAPPER_WORDS = new Set([
  'user', 'account', 'full', 'name', 'mac', 'address', 'hostname', 'host',
  'the', 'infected', 'was', 'identified', 'as',
  'client', 'ip', 'located', 'at', 'on', 'network',
])
/** Who/where delimiters: whitespace, punctuation, and ASCII quotes. */
const HANDLE_TOKEN_DELIMITERS = String.raw`\s,;:|/'"`
/**
 * Leftover MAC token. Colon is a who/where delimiter, so a word split
 * would shatter `aa:bb:cc:dd:ee:ff` into hex pairs. Dash MACs stay one
 * word; this pattern extracts both spellings as one token.
 */
const LEFTOVER_MAC_TOKEN = new RegExp(
  `(?<![^${HANDLE_TOKEN_DELIMITERS}])[0-9a-f]{2}(?:[:\\-][0-9a-f]{2}){5}(?![^${HANDLE_TOKEN_DELIMITERS}])`,
  'gi',
)
/**
 * Leftover CIDR token. `/` is a who/where delimiter, so a word split would
 * shatter `10.0.10.0/24` into a non-victim IPv4 plus a prefix number.
 * Extracted as one token; the handle-text check drops it when it contains
 * the bound victim IP.
 */
const LEFTOVER_CIDR_TOKEN = new RegExp(
  `(?<![^${HANDLE_TOKEN_DELIMITERS}])${IPV4_DOTTED}/${CIDR_PREFIX}(?![^${HANDLE_TOKEN_DELIMITERS}])`,
  'g',
)

/** Model-supplied who/where after deny/coerce, before the row fills omitted keys. */
export interface SubmittedIdentitySlots {
  /** Raw who argument, or omitted. */
  who?: unknown
  /** Raw where argument, or omitted. */
  where?: unknown
}

/** Cited conversation as submitted to bind_relationship. */
export interface BindRelationshipInput {
  /** Conversation source address. */
  src: string
  /** Conversation destination address. */
  dst: string
  /**
   * Destination port. A numeric string that is an integer is coerced before
   * the 1-65535 check. Omitted dport is not invented.
   */
  dport?: number | string
  /** Conversation time as submitted. */
  t: string
  /** Id of the cited conversation evidence. */
  evidence_id: string
}

/** Model or fold input before defaults and role checks. */
export interface BindRequest {
  /** Cited conversation. */
  relationship: BindRelationshipInput
  /**
   * Endpoints the model assigned. A JSON array string of endpoint objects is
   * coerced to that array before role checks. Missing src/dst are completed
   * with defaults.
   */
  endpoints: readonly BindEndpointInput[] | string
}

/** BindRequest after endpoints and dport coerce. */
export interface CoercedBindRequest {
  /** Cited conversation; dport is an integer when the input was a numeric string. */
  relationship: BindRelationshipInput
  /** Endpoint objects. */
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
  return normalizeIdentityValue('ip', addr)
}

/**
 * Whether an address is a cue/observation (external / detector) IP.
 * Those addresses default to role `c2` and cannot be assigned `victim`.
 * @param addr - normalized address.
 * @returns true for a unicast non-LAN IPv4.
 */
export function isCueObservationAddr(addr: string): boolean {
  return isIpv4(addr) && isNonLanUnicastIpv4(addr)
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
 * Coerce Hermes-stringified bind_relationship arguments before resolveBind.
 * A JSON array string of endpoint objects becomes that array. A numeric
 * string dport that is an integer becomes that integer. A string that is
 * not a JSON array stays rejected. A missing dport is not invented.
 * @param request - relationship plus submitted endpoints, possibly stringified.
 * @returns the coerced request with an endpoint array, or a deny reason.
 */
export function coerceBindRequest(request: BindRequest): CoercedBindRequest | string {
  const endpoints = coerceBindEndpoints(request.endpoints)
  if (endpoints === undefined) return ENDPOINTS_ARRAY_REASON
  const dport = coerceBindDport(request.relationship.dport)
  const relationship: BindRelationshipInput = {
    src: request.relationship.src,
    dst: request.relationship.dst,
    t: request.relationship.t,
    evidence_id: request.relationship.evidence_id,
  }
  if (dport !== undefined) relationship.dport = dport
  return { relationship, endpoints }
}

/**
 * Resolve and validate a BindRelationship request.
 * Missing src/dst endpoints are completed with default roles. Cue/observation
 * addresses default to `c2`. The cited conversation must include a
 * cue/observation address; a both-LAN conversation is unbound and does not
 * issue a hunt. Role `c2` cannot be a LAN address; tokens are not swapped.
 * Assigning `victim` to a cue/observation address is always unbound and names
 * the other-end hunt for that cue. Zero or two victims fail. A JSON array
 * string of endpoint objects and a numeric-string dport are coerced first;
 * a missing dport is not invented. These checks run on the coerced request.
 * @param request - relationship plus submitted endpoints.
 * @returns the bind, or a deny reason.
 */
export function resolveBind(request: BindRequest): BindResolution {
  const coerced = coerceBindRequest(request)
  if (typeof coerced === 'string') return { ok: false, reason: coerced }
  const relationship = normalizeRelationship(coerced.relationship)
  if (typeof relationship === 'string') return { ok: false, reason: relationship }
  if (!conversationIncludesCue(relationship.src, relationship.dst)) {
    return { ok: false, reason: BOTH_LAN_CONVERSATION_REASON }
  }

  const seen = new Set<string>()
  const endpoints: BoundEndpoint[] = []
  for (const input of coerced.endpoints) {
    const resolved = resolveEndpoint(input, seen)
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
 * `entity_id` wins. A MAC sourced from the bound victim IP on a tool-result
 * line (`ip.src`, outbound `ip → peer`, or ARP `is at`) affiliates to that
 * victim; a hunt-subject `evidence_id` does not veto that. A MAC whose
 * `evidence_id` is the victim IPv4 — including a field-only `eth.src` dump
 * scoped to that IP — affiliates to that victim even when the first harvest
 * had no `evidence_id` or a DC/peer stamp that a later victim-IP-scoped
 * dump overwrote. A user or full_name evidenced on a Kerberos/SAMR
 * conversation whose client is the bound victim affiliates to that victim;
 * hunt-subject `evidence_id` does not veto that. A hostname evidenced on an
 * IPv4 (hunt-subject `evidence_id`, or a name-service line scoped to that IP)
 * affiliates to that IP. Whole-ledger uniqueness does not block a
 * victim-IP-scoped MAC or hostname, or a conversation-client user or
 * full_name. A MAC sourced from the C2-talking LAN IP donates to that IP
 * when it matches the bound victim.
 * After a live bind, an unaffiliated identity (no `entity_id`, `evidence_id`
 * does not point at a non-victim) donates to the bound victim when it is the
 * only identity of that kind that is not affiliated with a different entity.
 * Distractors never donate.
 * @param identity - ledger identity.
 * @param bind - live bind.
 * @param identities - full ledger, used to resolve a sourced MAC and uniqueness.
 * @param evidenceText - tool-result text for victim-IP scope and C2-talking.
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
  const victim = victimOf(bind)
  if (victim !== undefined && evidencedOnVictimIp(identity, victim.addr, evidenceText)) {
    return victim.addr
  }
  const scoped = scopedIpForIdentity(identity, evidenceText)
  if (scoped !== undefined) return scoped
  if (identity.kind === 'mac') {
    const sourced = c2TalkingLanVictim(identities, evidenceText)
    if (
      sourced !== undefined
      && sourced.mac === identity.value
      && victim !== undefined
      && sourced.ip === victim.addr
    ) {
      return victim.addr
    }
  }
  if (
    victim !== undefined
    && uniqueUnaffiliatedOfKind(identity, victim, bind, identities, evidenceText)
  ) {
    return victim.addr
  }
  return undefined
}

/**
 * Whether an identity may donate a who/where slot for the bound victim.
 * Distractors and other non-victim entities cannot donate. An `evidence_id`
 * that names a non-victim entity also blocks donation, except a MAC sourced
 * from the bound victim IP on a tool-result line, a MAC whose `evidence_id`
 * is that victim (a victim-IP-scoped `eth.src` dump), or a user or full_name
 * whose conversation client is that victim: hunt-subject `evidence_id` does
 * not veto that. A MAC or hostname evidenced on the bound victim IP, or a
 * user or full_name whose conversation client is that victim, donates even
 * when other values of that kind exist on the ledger and even when the first
 * harvest had no `evidence_id` or a DC/peer stamp later overwritten by a
 * victim-IP-scoped dump. After a live bind, a unique unaffiliated
 * identity of a kind donates; two unaffiliated values of that kind donate
 * neither.
 * @param identity - ledger identity.
 * @param bind - live bind.
 * @param identities - full ledger.
 * @param evidenceText - tool-result text for victim-IP scope and C2-talking.
 * @returns true when the identity belongs to the unique victim.
 */
export function identityDonatesToVictim(
  identity: Identity,
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText = '',
): boolean {
  const victim = victimOf(bind)
  if (victim !== undefined && evidencedOnVictimIp(identity, victim.addr, evidenceText)) {
    return identity.entity_id === undefined || identity.entity_id === '' || identity.entity_id === victim.addr
  }
  if (pointsAtNonVictim(identity.evidence_id, bind)) return false
  if (victim === undefined) return false
  return entityIdForIdentity(identity, bind, identities, evidenceText) === victim.addr
}

/**
 * Project the victim entity row (IP / MAC / hostname / user / full_name).
 * @param bind - live bind with exactly one victim.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text for victim-IP scope and sourced-MAC affiliation.
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
  for (const kind of ['mac', 'hostname', 'user', 'full_name'] as const) {
    const value = first(kind)
    if (value !== undefined) slot[kind] = value
  }
  return slot
}

/**
 * Persist the projected victim row after deny/coerce.
 * Keys the model omitted are filled from that row. A donated victim-IP-sourced
 * MAC — including a field-only `eth.src` dump scoped to that IP — is copied
 * even when the model omits `mac`. When the row did not donate `mac`, the
 * unique ledger MAC that is not DC/gateway-only still persists. Talking-IP
 * frames that source a MAC only from a non-victim exclude that MAC.
 * Absence of talking-IP evidence is not DC-only. A sticky DC `entity_id` or
 * `evidence_id` is not the ownership test and does not hide a NIC that is
 * not proven DC-only. Several equally unproven MACs persist none. When the
 * row did not donate `user`, an omitted user still persists from victim-IP
 * evidence (conversation-client stamp). Uniqueness does not block an
 * omitted conversation-client user. A user that donates to a non-victim
 * and is not evidenced on the victim stays off. A submitted user,
 * hostname, or full_name is kept when the row has no donated value and
 * that identity does not donate to a different entity. A submitted mac is
 * kept unless talking-IP frames source that MAC only from a non-victim
 * (never as eth.src from the bound victim IP; never the NIC of that
 * victim). A submitted string that is not a six-octet MAC stays off.
 * A sticky DC `evidence_id` or donate does not override that submitted
 * MAC. A model-offered IP does not replace the bound victim ip.
 * Slots the row and frames do not evidence are not invented.
 * @param projected - victim entity row from {@link projectVictimSlot}.
 * @param submitted - raw who or where argument after deny/coerce, or omitted.
 * @param bind - live bind used to reject a value that donates elsewhere.
 * @param identities - folded ledger identities for that donate check.
 * @param evidenceText - tool-result text for victim-IP scope and conversation-client donate.
 * @returns the accepted slot: entity_id, ip, donated or unique non-DC-only
 * omitted mac, evidenced omitted user, donated hostname/full_name, kept
 * submitted mac unless talking-IP proves DC/gateway-only, and kept
 * submitted user/hostname/full_name.
 */
export function completeAcceptedSlot(
  projected: CaseIdentitySlot,
  submitted?: unknown,
  bind?: RelationshipBind,
  identities: readonly Identity[] = [],
  evidenceText = '',
): CaseIdentitySlot {
  const accepted: CaseIdentitySlot = { entity_id: projected.entity_id }
  const model = submittedSlotRecord(submitted)
  for (const key of SLOT_KEYS) {
    const donated = projected[key]
    if (donated !== undefined) {
      accepted[key] = donated
      continue
    }
    const offered = model?.[key]
    if (typeof offered === 'string' && offered.trim() !== '') {
      if (key === 'ip') continue
      const normalized = normalizeIdentityValue(key, offered)
      if (normalized === undefined) continue
      if (key === 'mac') {
        if (!MAC_HANDLE.test(normalized)) continue
        if (
          bind === undefined
          || !offeredMacEvidencedOnVictim(normalized, bind, evidenceText)
        ) {
          continue
        }
        accepted.mac = normalized
        continue
      }
      if (
        bind !== undefined
        && offeredDonatesToNonVictim(key, normalized, bind, identities, evidenceText)
      ) {
        continue
      }
      accepted[key] = normalized
      continue
    }
    if (bind === undefined) continue
    if (key === 'mac') {
      const evidenced = omittedMacEvidencedOnVictim(bind, identities, evidenceText)
      if (evidenced !== undefined) accepted.mac = evidenced
      continue
    }
    if (key === 'user') {
      const evidenced = omittedUserEvidencedOnVictim(bind, identities, evidenceText)
      if (evidenced !== undefined) accepted.user = evidenced
    }
  }
  return accepted
}

/**
 * Build the persisted case_report packet. who/where are the victim row.
 * Model-supplied who/where go through deny/coerce first; omitted keys are
 * filled from that projected row. Omitted mac persists the unique ledger
 * MAC that is not DC/gateway-only when a sticky DC donate or uniqueness
 * left the row empty. Omitted user still persists from victim-IP evidence.
 * A submitted user, hostname, or full_name is kept when the row has no
 * donated value and that identity does not donate to a different entity.
 * A submitted mac is kept unless talking-IP frames source that MAC only
 * from a non-victim. A harvested C2 DNS/SNI name persists as `c2_domain`
 * and does not fill who/where hostname.
 * @param bind - live bind.
 * @param identities - folded ledger identities.
 * @param claims - what / when / why / how.
 * @param evidenceText - tool-result text for victim-IP scope and sourced-MAC affiliation.
 * @param submitted - raw who/where after deny/coerce, or omitted.
 * @returns the report, or undefined when the bind has no unique victim.
 */
export function projectCaseReport(
  bind: RelationshipBind,
  identities: readonly Identity[],
  claims: CaseReportClaims,
  evidenceText = '',
  submitted: SubmittedIdentitySlots = {},
): CaseReport | undefined {
  const slot = projectVictimSlot(bind, identities, evidenceText)
  if (slot === undefined) return undefined
  const report: CaseReport = {
    who: completeAcceptedSlot(slot, submitted.who, bind, identities, evidenceText),
    what: claims.what,
    when: claims.when,
    where: completeAcceptedSlot(slot, submitted.where, bind, identities, evidenceText),
    why: claims.why,
    how: claims.how,
  }
  const domain = acceptedC2Domain(bind, identities)
  if (domain !== undefined) report.c2_domain = domain
  return report
}

/**
 * Project the close packet or throw when the bind has no unique victim.
 * @param bind - live bind, or undefined when unbound.
 * @param identities - folded ledger identities.
 * @param claims - what / when / why / how.
 * @param evidenceText - tool-result text for victim-IP scope and sourced-MAC affiliation.
 * @param submitted - raw who/where after deny/coerce, or omitted.
 * @returns the projected report.
 */
export function requireCaseReport(
  bind: RelationshipBind | undefined,
  identities: readonly Identity[],
  claims: CaseReportClaims,
  evidenceText = '',
  submitted: SubmittedIdentitySlots = {},
): CaseReport {
  if (bind === undefined) throw new Error(UNBOUND_REASON)
  const report = projectCaseReport(bind, identities, claims, evidenceText, submitted)
  if (report === undefined) throw new Error(UNBOUND_REASON)
  return report
}

/**
 * Deny reason for case_report or an attempt to set who/where.
 * Missing bind, a non-victim or other IPv4 entity_id, free-text who/where,
 * and identity slots whose evidence_id points at a non-victim all return
 * {@link UNBOUND_REASON}. A JSON object string with `entity_id` is coerced to
 * that object before the free-text check. After a live bind, a who/where
 * string whose leftover identity tokens are all victim-row handles (bound
 * victim IP, or a ledger user / full_name / hostname / MAC that donates to
 * that victim or is evidenced on that victim the same way omitted mac/user
 * persist) is coerced to `{ entity_id: victim.addr }`. Label words, locator
 * leftovers (client / ip / located / at / on / network), sentence wrappers,
 * wrapping ASCII quotes, a leftover MAC that talking-IP frames source only
 * from a non-victim, and a leftover CIDR that contains the bound victim IP
 * are not identity tokens. A multi-word full_name is one handle. A user,
 * hostname, MAC, or full_name is a victim-row handle, not an entity id; the
 * persisted packet still uses the victim address. A string that names the
 * c2, a distractor user or hostname, another IPv4 that is not that
 * victim-containing CIDR, a CIDR that does not contain the victim, or
 * unmatched leftover words stays unbound. A string that is only that
 * DC/gateway-only MAC, or that has no remaining victim-row handle, stays
 * unbound.
 * @param args - tool arguments.
 * @param bind - live bind, or undefined when unbound.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text for victim-IP-scoped handle donation.
 * @returns the deny reason, or undefined when the close may proceed.
 */
export function caseReportDenyReason(
  args: unknown,
  bind: RelationshipBind | undefined,
  identities: readonly Identity[] = [],
  evidenceText = '',
): string | undefined {
  const victim = bind === undefined ? undefined : victimOf(bind)
  if (bind === undefined || victim === undefined) return UNBOUND_REASON
  if (typeof args !== 'object' || args === null) return undefined
  const record = args as Record<string, unknown>
  for (const field of ['who', 'where'] as const) {
    const value = coerceIdentitySlotArg(record[field], bind, identities, victim, evidenceText)
    if (value === undefined) continue
    if (typeof value === 'string') return UNBOUND_REASON
    if (typeof value !== 'object' || value === null) return UNBOUND_REASON
    const slot = value as { entity_id?: unknown; evidence_id?: unknown }
    if (slot.entity_id !== undefined) {
      if (typeof slot.entity_id !== 'string') return UNBOUND_REASON
      const entityId = normalizeEndpointAddr(slot.entity_id)
      if (entityId === undefined) return UNBOUND_REASON
      if (namesNonVictimEndpoint(entityId, bind)) return UNBOUND_REASON
    }
    if (typeof slot.evidence_id === 'string' && pointsAtNonVictim(slot.evidence_id, bind, identities)) {
      return UNBOUND_REASON
    }
  }
  return undefined
}

/**
 * Whether a submitted entity_id names a non-victim conversation endpoint or
 * another IPv4. Those values stay inverted or unbound. A user, hostname, MAC,
 * or full_name is not an endpoint address.
 * @param entityId - normalized submitted entity id.
 * @param bind - live bind with exactly one victim.
 * @returns true when the close must stay denied.
 */
function namesNonVictimEndpoint(entityId: string, bind: RelationshipBind): boolean {
  const named = bind.endpoints.find(endpoint => endpoint.addr === entityId)
  if (named !== undefined) return named.role !== 'victim'
  return isIpv4(entityId)
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
 * @param evidenceText - tool-result text for victim-IP scope and sourced-MAC affiliation.
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

function normalizeRelationship(raw: BindRelationshipInput): Relationship | string {
  const src = normalizeEndpointAddr(raw.src)
  const dst = normalizeEndpointAddr(raw.dst)
  const evidenceId = raw.evidence_id.trim()
  const time = raw.t.trim()
  if (src === undefined || dst === undefined) {
    return 'bind_relationship relationship src and dst must be non-empty'
  }
  if (evidenceId === '') return 'bind_relationship relationship evidence_id must be a non-empty string'
  if (time === '') return 'bind_relationship relationship t must be a non-empty string'
  const dport = raw.dport
  if (typeof dport !== 'number' || !Number.isInteger(dport) || dport < 1 || dport > 65535) {
    return 'bind_relationship relationship dport must be an integer 1-65535'
  }
  return { src, dst, dport, t: time, evidence_id: evidenceId }
}

/**
 * Whether the cited conversation includes a cue/observation address.
 * @param src - normalized conversation source.
 * @param dst - normalized conversation destination.
 * @returns true when src or dst is a unicast non-LAN IPv4.
 */
function conversationIncludesCue(src: string, dst: string): boolean {
  return isCueObservationAddr(src) || isCueObservationAddr(dst)
}

/**
 * Unique non-LAN IPv4 bound as role `c2`.
 * @param bind - live bind.
 * @returns that address, or undefined when it is missing or not unique.
 */
function boundC2Ipv4(bind: RelationshipBind): string | undefined {
  const c2s = bind.endpoints.filter(endpoint => (
    endpoint.role === 'c2' && isNonLanUnicastIpv4(endpoint.addr)
  ))
  return c2s.length === 1 ? c2s[0]?.addr : undefined
}

/**
 * Coerce `endpoints` from a JSON array string into that array.
 * A native array is used as given. A string that is not a JSON array stays
 * rejected so resolveBind does not invent endpoints.
 * @param value - schema-accepted array or string.
 * @returns endpoint objects, or undefined when the value is not an array.
 */
function coerceBindEndpoints(
  value: readonly BindEndpointInput[] | string,
): readonly BindEndpointInput[] | undefined {
  if (typeof value !== 'string') return value
  try {
    const parsed: unknown = JSON.parse(value.trim())
    if (Array.isArray(parsed)) return parsed as BindEndpointInput[]
  } catch {
    // JSON.parse SyntaxError: not a JSON array. Keep rejecting.
  }
  return undefined
}

/**
 * Coerce `dport` from a numeric integer string into that integer.
 * A number is used as given. A missing or non-integer string is left so
 * normalizeRelationship can deny it. A port is not invented.
 * @param value - schema-accepted integer or string, or omitted.
 * @returns the integer, or the original value.
 */
function coerceBindDport(value: number | string | undefined): number | string | undefined {
  if (typeof value !== 'string') return value
  const text = value.trim()
  if (!INTEGER_STRING.test(text)) return value
  return Number(text)
}

function resolveEndpoint(
  input: BindEndpointInput,
  seen: Set<string>,
): BoundEndpoint | string {
  const addr = normalizeEndpointAddr(input.addr)
  if (addr === undefined) return 'bind_relationship endpoint addr must be a non-empty string'
  if (seen.has(addr)) return `bind_relationship endpoint ${addr} is duplicated`
  const because = input.because.trim()
  if (because === '') return 'bind_relationship endpoint because must be a non-empty string'
  const role = input.role ?? defaultRoleForAddr(addr)
  if (!ROLE_SET.has(role)) return `bind_relationship endpoint role ${JSON.stringify(input.role)} is not valid`
  if (role === 'victim' && isCueObservationAddr(addr)) return cueVictimUnboundReason(addr)
  if (role === 'c2' && isLanIpv4(addr)) return LAN_C2_REASON
  seen.add(addr)
  return { addr, role, because }
}

/**
 * Whether an unaffiliated identity is the only one of its kind that is not
 * affiliated with a different entity. Two unaffiliated values of the same kind
 * donate neither. A distractor with another endpoint's `entity_id` does not
 * count against uniqueness and does not donate. A MAC sourced to a non-victim
 * IP, or a user or full_name whose conversation client is a non-victim IP, is
 * affiliated with that other entity.
 * @param identity - candidate ledger identity (no explicit `entity_id`).
 * @param victim - unique victim endpoint on the live bind.
 * @param bind - live bind.
 * @param identities - full ledger.
 * @param evidenceText - tool-result text for victim-IP scope and sourced-MAC affiliation.
 * @returns true when this identity is the unique non-foreign value of its kind.
 */
function uniqueUnaffiliatedOfKind(
  identity: Identity,
  victim: BoundEndpoint,
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText: string,
): boolean {
  const candidates = identities.filter(other => (
    other.kind === identity.kind
    && !affiliatedWithDifferentEntity(other, victim.addr, identities, evidenceText)
    && !pointsAtNonVictim(other.evidence_id, bind, identities)
  ))
  const unique = candidates.length === 1 ? candidates[0] : undefined
  return unique !== undefined && unique.value === identity.value
}

/**
 * Whether an identity already belongs to an entity other than the bound victim.
 * Explicit `entity_id` wins. A MAC sourced from the bound victim IP on a
 * tool-result line belongs to that victim; hunt-subject `evidence_id` does not
 * affiliate it elsewhere. A user or full_name whose conversation client is
 * the bound victim belongs to that victim; hunt-subject `evidence_id` does
 * not affiliate it elsewhere. A hostname evidenced on another IPv4 belongs
 * to that IP. A MAC sourced from a C2-talking LAN IP belongs to that IP.
 * @param identity - ledger identity.
 * @param victimAddr - bound victim address.
 * @param identities - full ledger.
 * @param evidenceText - tool-result text for victim-IP scope and sourced-MAC affiliation.
 * @returns true when the identity is already tied to a different entity.
 */
function affiliatedWithDifferentEntity(
  identity: Identity,
  victimAddr: string,
  identities: readonly Identity[],
  evidenceText: string,
): boolean {
  if (identity.entity_id !== undefined && identity.entity_id !== '') {
    return identity.entity_id !== victimAddr
  }
  if (evidencedOnVictimIp(identity, victimAddr, evidenceText)) return false
  const scoped = scopedIpForIdentity(identity, evidenceText)
  if (scoped !== undefined) return scoped !== victimAddr
  if (identity.kind === 'mac') {
    const sourced = c2TalkingLanVictim(identities, evidenceText)
    if (sourced !== undefined && sourced.mac === identity.value) {
      return sourced.ip !== victimAddr
    }
  }
  return false
}

/**
 * IPv4 a MAC, hostname, user, or full_name is evidenced on. A MAC uses the
 * unique talking IP from tool-result frames (`ip.src`, outbound `ip → peer`,
 * or ARP `is at`); hunt-subject `evidence_id` does not win over that. A user
 * or full_name uses the unique conversation client (`ip.src`), or the
 * unique LAN / non-DC peer talking to a DC when the account line has no
 * IP. A stamped client `evidence_id` is not a hunt-subject DC and is not
 * passed into `conversationClientIp`. A hostname still uses hunt-subject
 * `evidence_id`, then a unique name-service line.
 * @param identity - ledger identity.
 * @param evidenceText - tool-result text.
 * @returns the scoped IPv4, or undefined when none is unique.
 */
function scopedIpForIdentity(identity: Identity, evidenceText: string): string | undefined {
  if (identity.kind === 'hostname') {
    const fromId = ipv4EvidenceId(identity.evidence_id)
    if (fromId !== undefined) return fromId
    const ips = ipsEvidencingIdentity(identity, evidenceText)
    return ips.length === 1 ? ips[0] : undefined
  }
  const ips = ipsEvidencingIdentity(identity, evidenceText)
  if (ips.length === 1) return ips[0]
  return ipv4EvidenceId(identity.evidence_id)
}

/**
 * Whether tool-result text or a restamped `evidence_id` evidences this
 * identity on `victimAddr`. A MAC is sourced from that IP (`ip.src`,
 * outbound `ip → peer`, or ARP `is at`), or carries `evidence_id` of that
 * IP from a victim-IP-scoped `eth.src` dump. A user or full_name is on a
 * Kerberos/SAMR conversation whose client is that IP, or a field-only
 * SAMR/CName line whose evidence text names that client talking to a DC.
 * Hostname uses hunt-subject or name-service scope and is not selected here.
 * @param identity - ledger identity.
 * @param victimAddr - bound victim IPv4.
 * @param evidenceText - tool-result text.
 * @returns true when this identity is evidenced on that IP.
 */
function evidencedOnVictimIp(identity: Identity, victimAddr: string, evidenceText: string): boolean {
  if (identity.kind === 'mac' && ipv4EvidenceId(identity.evidence_id) === victimAddr) return true
  if (identity.kind !== 'mac' && identity.kind !== 'user' && identity.kind !== 'full_name') {
    return false
  }
  return ipsEvidencingIdentity(identity, evidenceText).includes(victimAddr)
}

/**
 * Whether `evidence_id` is an IPv4 used as a hunt subject or entity scope.
 * @param evidenceId - identity evidence id.
 * @returns the normalized IPv4, or undefined when the id is not an IPv4.
 */
function ipv4EvidenceId(evidenceId: string | undefined): string | undefined {
  if (evidenceId === undefined || evidenceId === '') return undefined
  const ip = normalizeEndpointAddr(evidenceId)
  return ip !== undefined && isIpv4(ip) ? ip : undefined
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
  return IPV4_EXACT.test(addr)
}

/**
 * Unique ledger MAC that is not DC/gateway-only.
 * Talking-IP frames that source a MAC only from a non-victim exclude that
 * MAC. A sticky DC `entity_id` or `evidence_id` does not hide a NIC that
 * is not proven DC-only. Several equally unproven MACs return undefined.
 * @param bind - live bind.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text.
 * @returns the unique non-DC-only MAC, or undefined when none is unique.
 */
function omittedMacEvidencedOnVictim(
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText: string,
): string | undefined {
  const victim = victimOf(bind)
  if (victim === undefined) return undefined
  const values = new Set<string>()
  for (const identity of identities) {
    if (identity.kind !== 'mac') continue
    if (macIsDcOrGatewayOnly(identity.value, victim.addr, evidenceText)) continue
    values.add(identity.value)
  }
  return values.size === 1 ? [...values][0] : undefined
}

/**
 * First ledger user evidenced on the bound victim.
 * A Kerberos/SAMR conversation whose client is that IP, or a
 * conversation-client `evidence_id` of that IP, qualifies. Uniqueness does
 * not block. A sticky DC `entity_id` does not skip that user. A user that
 * only donates to a non-victim is not returned.
 * @param bind - live bind.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text.
 * @returns the first evidenced user, or undefined when none exists.
 */
function omittedUserEvidencedOnVictim(
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText: string,
): string | undefined {
  const victim = victimOf(bind)
  if (victim === undefined) return undefined
  for (const identity of identities) {
    if (identity.kind !== 'user') continue
    if (evidencedOnVictimIp(identity, victim.addr, evidenceText)) return identity.value
    if (ipv4EvidenceId(identity.evidence_id) === victim.addr) return identity.value
  }
  return undefined
}

/**
 * Whether talking-IP frames source this MAC only from a non-victim.
 * Absence of talking-IP evidence is not DC/gateway-only. Ledger
 * `evidence_id`, `entity_id`, and first-donate are not this test.
 * @param mac - normalized MAC.
 * @param victimAddr - bound victim IPv4.
 * @param evidenceText - tool-result text.
 * @returns true when every talking IP is a non-victim.
 */
function macIsDcOrGatewayOnly(mac: string, victimAddr: string, evidenceText: string): boolean {
  const talkingIps = ipsEvidencingIdentity({ kind: 'mac', value: mac, label: 'MAC' }, evidenceText)
  if (talkingIps.length === 0) return false
  return talkingIps.every(ip => ip !== victimAddr)
}

/**
 * Whether a model-offered MAC may persist on the bound victim.
 * Persist unless talking-IP frames source that MAC only from a non-victim.
 * A sticky DC `evidence_id` or `entity_id` is not DC-only. Absence of
 * talking-IP evidence is not DC-only.
 * @param mac - normalized offered MAC.
 * @param bind - live bind.
 * @param evidenceText - tool-result text.
 * @returns true when the MAC is not DC/gateway-only.
 */
function offeredMacEvidencedOnVictim(
  mac: string,
  bind: RelationshipBind,
  evidenceText: string,
): boolean {
  const victim = victimOf(bind)
  if (victim === undefined) return false
  return !macIsDcOrGatewayOnly(mac, victim.addr, evidenceText)
}

/**
 * Whether a model-offered hostname, user, or full_name already donates to
 * an entity other than the bound victim. A value that is not on the ledger,
 * or that does not resolve to another entity, does not donate elsewhere.
 * @param kind - offered slot kind.
 * @param value - normalized offered value.
 * @param bind - live bind.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text for scoped donate.
 * @returns true when the offered identity belongs to a non-victim entity.
 */
function offeredDonatesToNonVictim(
  kind: 'hostname' | 'user' | 'full_name',
  value: string,
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText: string,
): boolean {
  const victim = victimOf(bind)
  if (victim === undefined) return false
  const identity = identities.find(item => item.kind === kind && item.value === value)
  if (identity === undefined) return false
  const entityId = entityIdForIdentity(identity, bind, identities, evidenceText)
  return entityId !== undefined && entityId !== victim.addr
}

/**
 * Model-supplied who/where as a record of slot keys, when the argument is an
 * object or a JSON object string. A handle string is not a slot record.
 * @param submitted - raw who or where argument.
 * @returns the object, or undefined when there are no model slot keys.
 */
function submittedSlotRecord(submitted: unknown): Record<string, unknown> | undefined {
  let value = submitted
  if (typeof submitted === 'string') {
    const text = submitted.trim()
    if (!text.startsWith('{')) return undefined
    try {
      value = JSON.parse(text) as unknown
    } catch {
      // JSON.parse SyntaxError: not a JSON object. Treat as no model keys.
      return undefined
    }
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

/**
 * Coerce a JSON object string into that object, or a victim-row handle string
 * into `{ entity_id: victim.addr }`. Hermes XML recovery stores object
 * parameters as trimmed JSON text, so who/where can arrive as strings. After a
 * live bind, a string whose leftover identity tokens are all victim-row
 * handles projects through the existing victim-row path, including labeled or
 * sentence-wrapped handles. Locator leftovers are wrappers. A leftover CIDR
 * that contains the bound victim IP is dropped. A leftover MAC that
 * talking-IP frames source only from a non-victim is dropped. A string that
 * is not a JSON object and not a victim-row handle stays a string for the
 * free-text deny.
 * @param value - raw who/where argument.
 * @param bind - live bind with exactly one victim.
 * @param identities - folded ledger identities.
 * @param victim - unique victim endpoint on that bind.
 * @param evidenceText - tool-result text for victim-IP-scoped handles.
 * @returns the parsed or projected object, or the original value.
 */
function coerceIdentitySlotArg(
  value: unknown,
  bind: RelationshipBind,
  identities: readonly Identity[],
  victim: BoundEndpoint,
  evidenceText = '',
): unknown {
  if (typeof value !== 'string') return value
  const text = value.trim()
  if (text.startsWith('{')) {
    try {
      return JSON.parse(text) as unknown
    } catch {
      // JSON.parse SyntaxError: not a JSON object. Keep the string for the free-text deny.
      return value
    }
  }
  if (!isVictimHandleText(text, bind, identities, victim, evidenceText)) return value
  return { entity_id: victim.addr }
}

/**
 * Whether leftover identity tokens in `text` are all victim-row handles.
 * The whole trimmed string may itself be one handle (user, full_name,
 * hostname, MAC, or bound victim IP). Label words, locator leftovers,
 * sentence wrappers, wrapping ASCII quotes, a leftover MAC that talking-IP
 * frames source only from a non-victim, and a leftover CIDR that contains
 * the bound victim IP are ignored. A multi-word full_name is one handle.
 * An empty leftover set, including a string that is only that
 * DC/gateway-only MAC or only that victim-containing CIDR, is not a
 * victim-row handle.
 * @param text - trimmed who/where string.
 * @param bind - live bind with exactly one victim.
 * @param identities - folded ledger identities.
 * @param victim - unique victim endpoint on that bind.
 * @param evidenceText - tool-result text for victim-IP-scoped handles.
 * @returns true when leftover tokens name only the bound victim row.
 */
function isVictimHandleText(
  text: string,
  bind: RelationshipBind,
  identities: readonly Identity[],
  victim: BoundEndpoint,
  evidenceText = '',
): boolean {
  const handles = victimRowHandles(bind, identities, victim, evidenceText)
  if (matchesVictimHandle(text, handles)) return true
  const tokens = identityLikeTokens(text, handles)
    .filter(token => !dcOrGatewayOnlyMacToken(token, victim.addr, evidenceText))
    .filter(token => !leftoverCidrContainsVictim(token, victim.addr))
  return tokens.length > 0 && tokens.every(token => matchesVictimHandle(token, handles))
}

/**
 * Whether one leftover token is a MAC that talking-IP frames source only
 * from a non-victim. The same DC/gateway-only test as persist. ip,
 * hostname, user, and full_name are never dropped here.
 * @param token - one leftover identity-like token.
 * @param victimAddr - bound victim IPv4.
 * @param evidenceText - tool-result text.
 * @returns true when the token may be ignored during handle-string coerce.
 */
function dcOrGatewayOnlyMacToken(token: string, victimAddr: string, evidenceText: string): boolean {
  const mac = normalizeIdentityValue('mac', token)
  return mac !== undefined && MAC_HANDLE.test(mac) && macIsDcOrGatewayOnly(mac, victimAddr, evidenceText)
}

/**
 * Whether one leftover token is an IPv4/prefix CIDR that contains the bound
 * victim IP. `/` is a who/where delimiter, so the CIDR must already be one
 * token. A CIDR that does not contain the victim stays unmatched. ip,
 * hostname, user, and full_name are never dropped here.
 * @param token - one leftover identity-like token.
 * @param victimAddr - bound victim IPv4.
 * @returns true when the token may be ignored during handle-string coerce.
 */
function leftoverCidrContainsVictim(token: string, victimAddr: string): boolean {
  const match = token.match(CIDR_EXACT)
  if (match === null) return false
  const network = match[1] as string
  const prefix = Number(match[2])
  if (!isIpv4(victimAddr) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false
  const ipInt = ipv4ToInt(victimAddr)
  const netInt = ipv4ToInt(network)
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0
  return (ipInt & mask) === (netInt & mask)
}

/**
 * Unsigned 32-bit value of a dotted IPv4.
 * @param ip - dotted IPv4 already proven by {@link isIpv4}.
 * @returns the integer.
 */
function ipv4ToInt(ip: string): number {
  let value = 0
  for (const part of ip.split('.')) value = (value << 8) + Number(part)
  return value >>> 0
}

/**
 * Bound victim address plus ledger user / full_name / hostname / MAC
 * (and IP) values that donate to that row or are evidenced on that
 * victim the same way omitted mac/user persist (victim-IP frames /
 * conversation-client stamp). A sticky DC donate does not drop a
 * victim-IP-sourced MAC or conversation-client user from this set.
 * @param bind - live bind with exactly one victim.
 * @param identities - folded ledger identities.
 * @param victim - unique victim endpoint on that bind.
 * @param evidenceText - tool-result text for victim-IP-scoped donation.
 * @returns normalized handle values.
 */
function victimRowHandles(
  bind: RelationshipBind,
  identities: readonly Identity[],
  victim: BoundEndpoint,
  evidenceText = '',
): Set<string> {
  const handles = new Set<string>([victim.addr])
  for (const identity of identities) {
    if (identityDonatesToVictim(identity, bind, identities, evidenceText)) {
      handles.add(identity.value)
      continue
    }
    if (identityEvidencedOnVictimRow(identity, victim.addr, evidenceText)) handles.add(identity.value)
  }
  return handles
}

/**
 * Whether a ledger identity is evidenced on the bound victim the same
 * way omitted mac/user persist. A sticky DC `entity_id` does not veto
 * victim-IP frames or a conversation-client stamp.
 * @param identity - ledger identity.
 * @param victimAddr - bound victim IPv4.
 * @param evidenceText - tool-result text.
 * @returns true when this value may be used as a victim-row handle.
 */
function identityEvidencedOnVictimRow(
  identity: Identity,
  victimAddr: string,
  evidenceText: string,
): boolean {
  if (identity.kind === 'mac' || identity.kind === 'full_name') {
    return evidencedOnVictimIp(identity, victimAddr, evidenceText)
  }
  if (identity.kind === 'user') {
    return evidencedOnVictimIp(identity, victimAddr, evidenceText)
      || ipv4EvidenceId(identity.evidence_id) === victimAddr
  }
  if (identity.kind === 'hostname') {
    return ipv4EvidenceId(identity.evidence_id) === victimAddr
      || ipsEvidencingIdentity(identity, evidenceText).includes(victimAddr)
  }
  return false
}

/**
 * Whether one token matches a victim-row handle under any identity normalize.
 * @param token - one identity-like token or the whole string.
 * @param handles - victim-row handle values.
 * @returns true when the token is a handle on that row.
 */
function matchesVictimHandle(token: string, handles: Set<string>): boolean {
  for (const kind of HANDLE_KINDS) {
    const normalized = normalizeIdentityValue(kind, token)
    if (normalized !== undefined && handles.has(normalized)) return true
  }
  return false
}

/**
 * Identity tokens: parenthesized groups, then victim-row handles in the
 * remaining text (longest match, so a multi-word full_name stays one
 * token), then leftover MAC-shaped tokens (colon or dash), then leftover
 * CIDR tokens (IPv4/prefix, extracted before `/` can shatter them), then
 * leftover words that are not field labels, locator leftovers, sentence
 * wrappers, or wrapping ASCII quotes. A leftover DC/gateway-only MAC and a
 * leftover CIDR that contains the bound victim IP are dropped by the
 * handle-text check, not here. Unmatched leftover tokens fail the
 * victim-row handle check.
 * @param text - trimmed who/where string.
 * @param handles - victim-row handle values used for longest-match extract.
 * @returns tokens in encounter order.
 */
function identityLikeTokens(text: string, handles: ReadonlySet<string> = new Set()): string[] {
  const tokens: string[] = []
  const mask = [...text]
  for (const match of text.matchAll(/\(([^)]*)\)/g)) {
    const inner = (match[1] as string).trim()
    if (inner !== '') tokens.push(inner)
    const start = match.index as number
    mask.fill(' ', start, start + match[0].length)
  }
  const sorted = [...handles].sort((left, right) => right.length - left.length)
  for (const handle of sorted) {
    for (const variant of handleSearchVariants(handle)) {
      const remainder = mask.join('')
      for (const match of remainder.matchAll(handleBoundaryPattern(variant))) {
        const start = match.index as number
        const end = start + match[0].length
        tokens.push(handle)
        mask.fill(' ', start, end)
      }
    }
  }
  const remainder = mask.join('')
  for (const match of remainder.matchAll(LEFTOVER_MAC_TOKEN)) {
    const start = match.index as number
    tokens.push(match[0])
    mask.fill(' ', start, start + match[0].length)
  }
  const afterMac = mask.join('')
  for (const match of afterMac.matchAll(LEFTOVER_CIDR_TOKEN)) {
    const start = match.index as number
    tokens.push(match[0])
    mask.fill(' ', start, start + match[0].length)
  }
  for (const match of mask.join('').matchAll(new RegExp(`[^${HANDLE_TOKEN_DELIMITERS}]+`, 'g'))) {
    if (!HANDLE_WRAPPER_WORDS.has(match[0].toLowerCase())) tokens.push(match[0])
  }
  return tokens
}

/**
 * Search spellings for one victim-row handle. A colon MAC also matches dashes.
 * @param handle - normalized handle value.
 * @returns spellings to look for in who/where text.
 */
function handleSearchVariants(handle: string): string[] {
  return MAC_HANDLE.test(handle) ? [handle, handle.replace(/:/g, '-')] : [handle]
}

/**
 * Case-insensitive handle match bounded by start/end or a who/where
 * delimiter (whitespace, punctuation, or an ASCII quote).
 * @param handle - one search spelling.
 * @returns the global match pattern.
 */
function handleBoundaryPattern(handle: string): RegExp {
  const escaped = handle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(
    `(?<![^${HANDLE_TOKEN_DELIMITERS}])${escaped}(?![^${HANDLE_TOKEN_DELIMITERS}])`,
    'gi',
  )
}
