/** Package-owned durable investigation-ledger invariants. @module @deepseek-ai/dsh-investigation/invariant */

import type { Context } from '@deepseek-ai/cordis'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import type { InvariantFailure, InvariantInstaller } from '@deepseek-ai/dsh-invariants'
import { ENDPOINT_ROLES } from './bind.ts'

const PACKAGE_NAME = '@deepseek-ai/dsh-investigation'
const IDENTITY_KINDS = new Set(['ip', 'mac', 'hostname', 'user', 'full_name'])
const HUNT_KINDS = new Set([
  'kerberos-cname', 'samr-userinfo', 'eth-src', 'name-service', 'other-end', 'c2-domain',
  'extra-wan',
])
const HUNT_SUBJECTS = new Set(['ip', 'hostname', 'user'])
const ROLE_SET = new Set<string>(ENDPOINT_ROLES)
const CLAIM_FIELDS = ['what', 'when', 'why', 'how'] as const
const SLOT_FIELDS = ['ip', 'mac', 'hostname', 'user'] as const
const CUE_VALIDATIONS = new Set(['valid', 'open', 'invalid'])
const CANDIDATE_LABELS = new Set(['victim', 'c2', 'dc', 'cdn', 'update', 'distractor'])
const THESIS_RESULTS = new Set(['confirm', 'kill', 'gap'])

/** Cordis companion plugin name. */
export const name = 'investigation-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/** Require a non-empty already-trimmed string. */
function requireText(value: unknown, label: string, fail: InvariantFailure): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    fail(`${label} must be a non-empty already-trimmed string`)
  }
}

/**
 * Validate one investigation event before it reaches the durable log.
 * @param event - candidate session event.
 * @param fail - reporter invoked with a human-readable reason.
 */
function validateEvent(event: SessionEvent, fail: InvariantFailure): void {
  if (event.type === 'investigation/identity') {
    const { kind, value, label, entity_id, evidence_id } = event.data as {
      kind?: unknown
      value?: unknown
      label?: unknown
      entity_id?: unknown
      evidence_id?: unknown
    }
    if (typeof kind !== 'string' || !IDENTITY_KINDS.has(kind)) {
      fail(`investigation/identity carries unknown kind ${JSON.stringify(kind)}`)
    }
    requireText(value, 'investigation/identity value', fail)
    requireText(label, 'investigation/identity label', fail)
    if (entity_id !== undefined) requireText(entity_id, 'investigation/identity entity_id', fail)
    if (evidence_id !== undefined) requireText(evidence_id, 'investigation/identity evidence_id', fail)
    return
  }
  if (event.type === 'investigation/hunt') {
    const { kind, subjectKind, subject } = event.data as {
      kind?: unknown
      subjectKind?: unknown
      subject?: unknown
    }
    if (typeof kind !== 'string' || !HUNT_KINDS.has(kind)) {
      fail(`investigation/hunt carries unknown kind ${JSON.stringify(kind)}`)
    }
    if (typeof subjectKind !== 'string' || !HUNT_SUBJECTS.has(subjectKind)) {
      fail(`investigation/hunt carries unknown subjectKind ${JSON.stringify(subjectKind)}`)
    }
    requireText(subject, 'investigation/hunt subject', fail)
    return
  }
  if (event.type === 'investigation/bind') {
    const data = event.data as {
      relationship?: {
        src?: unknown
        dst?: unknown
        dport?: unknown
        t?: unknown
        evidence_id?: unknown
      }
      endpoints?: unknown
    }
    const relationship = data.relationship
    if (relationship === undefined) fail('investigation/bind relationship is required')
    else {
      requireText(relationship.src, 'investigation/bind relationship.src', fail)
      requireText(relationship.dst, 'investigation/bind relationship.dst', fail)
      requireText(relationship.t, 'investigation/bind relationship.t', fail)
      requireText(relationship.evidence_id, 'investigation/bind relationship.evidence_id', fail)
      if (!Number.isInteger(relationship.dport)) {
        fail('investigation/bind relationship.dport must be an integer')
      }
    }
    if (!Array.isArray(data.endpoints) || data.endpoints.length === 0) {
      fail('investigation/bind endpoints must be a non-empty array')
    }
    else {
      for (const endpoint of data.endpoints) {
        if (typeof endpoint !== 'object' || endpoint === null) {
          fail('investigation/bind endpoint must be an object')
          continue
        }
        const row = endpoint as { addr?: unknown; role?: unknown; because?: unknown }
        requireText(row.addr, 'investigation/bind endpoint.addr', fail)
        requireText(row.because, 'investigation/bind endpoint.because', fail)
        if (typeof row.role !== 'string' || !ROLE_SET.has(row.role)) {
          fail(`investigation/bind endpoint.role ${JSON.stringify(row.role)} is not valid`)
        }
      }
    }
    return
  }
  if (event.type === 'investigation/mission') {
    const data = event.data as {
      purpose?: unknown
      slots?: unknown
      closedMeans?: unknown
      cue?: { addr?: unknown; evidence_id?: unknown }
      cueValidation?: unknown
    }
    requireText(data.purpose, 'investigation/mission purpose', fail)
    if (typeof data.cueValidation !== 'string' || !CUE_VALIDATIONS.has(data.cueValidation)) {
      fail(`investigation/mission cueValidation ${JSON.stringify(data.cueValidation)} is not valid`)
    }
    if (typeof data.cue !== 'object' || data.cue === null) {
      fail('investigation/mission cue must be an object')
    } else {
      requireText(data.cue.addr, 'investigation/mission cue.addr', fail)
      requireText(data.cue.evidence_id, 'investigation/mission cue.evidence_id', fail)
    }
    if (!Array.isArray(data.closedMeans)) {
      fail('investigation/mission closedMeans must be an array')
    } else {
      for (const [index, item] of data.closedMeans.entries()) {
        requireText(item, `investigation/mission closedMeans[${index}]`, fail)
      }
    }
    if (typeof data.slots !== 'object' || data.slots === null || Array.isArray(data.slots)) {
      fail('investigation/mission slots must be an object')
    }
    return
  }
  if (event.type === 'investigation/plan') {
    const data = event.data as {
      inventory?: unknown
      gaps?: unknown
      hypotheses?: unknown
    }
    validateStringList(data.inventory, 'investigation/plan inventory', fail)
    validateStringList(data.gaps, 'investigation/plan gaps', fail)
    if (data.hypotheses !== undefined) {
      if (!Array.isArray(data.hypotheses)) {
        fail('investigation/plan hypotheses must be an array')
      } else {
        for (const [index, row] of data.hypotheses.entries()) {
          if (typeof row !== 'object' || row === null) {
            fail(`investigation/plan hypotheses[${index}] must be an object`)
            continue
          }
          const hypothesis = row as {
            id?: unknown
            claim?: unknown
            disconfirm?: unknown
            label?: unknown
          }
          requireText(hypothesis.id, `investigation/plan hypotheses[${index}].id`, fail)
          requireText(hypothesis.claim, `investigation/plan hypotheses[${index}].claim`, fail)
          requireText(hypothesis.disconfirm, `investigation/plan hypotheses[${index}].disconfirm`, fail)
          if (typeof hypothesis.label !== 'string' || !CANDIDATE_LABELS.has(hypothesis.label)) {
            fail(`investigation/plan hypotheses[${index}].label ${JSON.stringify(hypothesis.label)} is not valid`)
          }
        }
      }
    }
    return
  }
  if (event.type === 'investigation/action') {
    const data = event.data as {
      huntKind?: unknown
      subject?: unknown
      hypothesis_id?: unknown
      evidence_id?: unknown
      thesis?: {
        name?: unknown
        claim?: unknown
        rule?: unknown
        result?: unknown
      }
    }
    if (typeof data.huntKind !== 'string' || !HUNT_KINDS.has(data.huntKind)) {
      fail(`investigation/action carries unknown huntKind ${JSON.stringify(data.huntKind)}`)
    }
    requireText(data.subject, 'investigation/action subject', fail)
    requireText(data.hypothesis_id, 'investigation/action hypothesis_id', fail)
    if (data.evidence_id !== undefined) requireText(data.evidence_id, 'investigation/action evidence_id', fail)
    const thesis = data.thesis
    if (thesis === undefined || typeof thesis !== 'object' || thesis === null) {
      fail('investigation/action thesis is required')
    } else {
      requireText(thesis.name, 'investigation/action thesis.name', fail)
      requireText(thesis.claim, 'investigation/action thesis.claim', fail)
      requireText(thesis.rule, 'investigation/action thesis.rule', fail)
      if (typeof thesis.result !== 'string' || !THESIS_RESULTS.has(thesis.result)) {
        fail(`investigation/action thesis.result ${JSON.stringify(thesis.result)} is not valid`)
      }
    }
    return
  }
  if (event.type === 'investigation/extras') {
    validateExtras(event.data, 'investigation/extras', fail)
    return
  }
  if (event.type !== 'investigation/report') return
  const data = event.data
  for (const field of CLAIM_FIELDS) {
    requireText(data[field], `investigation/report ${field}`, fail)
  }
  validateSlot(data.who, 'investigation/report who', fail)
  validateSlot(data.where, 'investigation/report where', fail)
  if (data.victims !== undefined) {
    if (!Array.isArray(data.victims) || data.victims.length < 2) {
      fail('investigation/report victims must be an array of two or more identity slots')
    } else {
      for (const [index, row] of data.victims.entries()) {
        validateSlot(row, `investigation/report victims[${index}]`, fail)
      }
    }
  }
  if (data.c2_domain !== undefined) requireText(data.c2_domain, 'investigation/report c2_domain', fail)
  if (data.c2_ips !== undefined) {
    if (!Array.isArray(data.c2_ips) || data.c2_ips.length === 0) {
      fail('investigation/report c2_ips must be a non-empty array')
    } else {
      for (const [index, ip] of data.c2_ips.entries()) {
        requireText(ip, `investigation/report c2_ips[${index}]`, fail)
      }
    }
  }
}

function validateStringList(value: unknown, label: string, fail: InvariantFailure): void {
  if (value === undefined) return
  if (!Array.isArray(value)) {
    fail(`${label} must be an array`)
    return
  }
  for (const [index, item] of value.entries()) {
    requireText(item, `${label}[${index}]`, fail)
  }
}

function validateExtras(data: {
  c2_domain?: unknown
  c2_ips?: unknown
  killed?: unknown
}, label: string, fail: InvariantFailure): void {
  if (data.c2_domain !== undefined) requireText(data.c2_domain, `${label} c2_domain`, fail)
  if (data.c2_ips !== undefined) {
    if (!Array.isArray(data.c2_ips) || data.c2_ips.length === 0) {
      fail(`${label} c2_ips must be a non-empty array`)
    } else {
      for (const [index, ip] of data.c2_ips.entries()) {
        requireText(ip, `${label} c2_ips[${index}]`, fail)
      }
    }
  }
  if (data.killed !== undefined) {
    if (!Array.isArray(data.killed) || data.killed.length === 0) {
      fail(`${label} killed must be a non-empty array`)
    } else {
      for (const [index, id] of data.killed.entries()) {
        requireText(id, `${label} killed[${index}]`, fail)
      }
    }
  }
  if (data.c2_domain === undefined && data.c2_ips === undefined && data.killed === undefined) {
    fail(`${label} must set c2_ips, c2_domain, or killed`)
  }
}

function validateSlot(value: unknown, label: string, fail: InvariantFailure): void {
  if (typeof value !== 'object' || value === null) {
    fail(`${label} must be a projected identity slot`)
    return
  }
  const slot = value as { entity_id?: unknown } & Record<string, unknown>
  requireText(slot.entity_id, `${label}.entity_id`, fail)
  for (const field of SLOT_FIELDS) {
    if (slot[field] === undefined) continue
    requireText(slot[field], `${label}.${field}`, fail)
  }
}

/* jscpd:ignore-start -- package companions share replay and dispatch plumbing */
/** Install validation for loaded and newly appended investigation events. */
const install: InvariantInstaller = Object.assign((ctx: Context, fail: InvariantFailure) => {
  const seed = (session: Session): void => {
    for (const event of session.events) validateEvent(event, fail)
  }
  for (const session of ctx.sessions.list()) seed(session)
  ctx.on('session/created', (session) => { seed(session) }, { global: true })
  ctx.on('internal/dispatch', (_mode, eventName, args) => {
    if (eventName !== 'session/event') return
    const [, event] = args as [Session, SessionEvent]
    validateEvent(event, fail)
  }, { global: true })
}, { inject: ['sessions'] })
/* jscpd:ignore-end */

/**
 * Register the investigation invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install))
