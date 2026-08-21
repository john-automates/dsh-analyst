/** Package-owned durable investigation-ledger invariants. @module @deepseek-ai/dsh-investigation/invariant */

import type { Context } from '@deepseek-ai/cordis'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import type { InvariantFailure, InvariantInstaller } from '@deepseek-ai/dsh-invariants'
import { ENDPOINT_ROLES } from './bind.ts'

const PACKAGE_NAME = '@deepseek-ai/dsh-investigation'
const IDENTITY_KINDS = new Set(['ip', 'mac', 'hostname', 'user', 'full_name'])
const HUNT_KINDS = new Set(['kerberos-cname', 'samr-userinfo', 'eth-src', 'name-service'])
const HUNT_SUBJECTS = new Set(['ip', 'hostname', 'user'])
const ROLE_SET = new Set<string>(ENDPOINT_ROLES)
const CLAIM_FIELDS = ['what', 'when', 'why', 'how'] as const
const SLOT_FIELDS = ['ip', 'mac', 'hostname', 'user'] as const

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
  if (event.type !== 'investigation/report') return
  const data = event.data as Record<string, unknown>
  for (const field of CLAIM_FIELDS) {
    requireText(data[field], `investigation/report ${field}`, fail)
  }
  validateSlot(data.who, 'investigation/report who', fail)
  validateSlot(data.where, 'investigation/report where', fail)
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
