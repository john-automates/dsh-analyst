/** Package-owned durable investigation-ledger invariants. @module @deepseek-ai/dsh-investigation/invariant */

import type { Context } from '@deepseek-ai/cordis'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import type { InvariantFailure, InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = '@deepseek-ai/dsh-investigation'
const IDENTITY_KINDS = new Set(['ip', 'mac', 'hostname', 'user', 'full_name'])
const HUNT_KINDS = new Set(['kerberos-cname', 'samr-userinfo', 'eth-src', 'name-service'])
const HUNT_SUBJECTS = new Set(['ip', 'hostname', 'user'])
const REPORT_FIELDS = ['who', 'what', 'when', 'where', 'why', 'how'] as const

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
    const { kind, value, label } = event.data as { kind?: unknown; value?: unknown; label?: unknown }
    if (typeof kind !== 'string' || !IDENTITY_KINDS.has(kind)) {
      fail(`investigation/identity carries unknown kind ${JSON.stringify(kind)}`)
    }
    requireText(value, 'investigation/identity value', fail)
    requireText(label, 'investigation/identity label', fail)
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
  if (event.type !== 'investigation/report') return
  const data = event.data
  for (const field of REPORT_FIELDS) {
    requireText(data[field], `investigation/report ${field}`, fail)
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
