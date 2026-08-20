/**
 * Investigation ledger types: the one home of the identity, hunt, and 5W1H
 * report records persisted on the session log.
 *
 * @module @deepseek-ai/dsh-investigation/types
 */

/** Labeled identity kinds harvested from tool results. */
export type IdentityKind = 'ip' | 'mac' | 'hostname' | 'user' | 'full_name'

/** One unique labeled identity folded from `investigation/identity` events. */
export interface Identity {
  /** Identity kind. */
  kind: IdentityKind
  /** Normalized value (lowercase MAC/hostname; trimmed otherwise). */
  value: string
  /** Human label shown to the model (`IP`, `MAC`, `hostname`, `user`, `full name`). */
  label: string
}

/** Auto-issued or recorded hunt kinds. */
export type HuntKind = 'kerberos-cname' | 'samr-userinfo'

/** Subject kinds a hunt can attach to. */
export type HuntSubjectKind = 'ip' | 'hostname' | 'user'

/** One hunt folded from `investigation/hunt` events. */
export interface Hunt {
  /** Hunt kind. */
  kind: HuntKind
  /** What the hunt is scoped to. */
  subjectKind: HuntSubjectKind
  /** Normalized subject value. */
  subject: string
}

/** 5W1H case-close packet stored on `investigation/report`. */
export interface CaseReport {
  /** Who was involved. */
  who: string
  /** What happened. */
  what: string
  /** When it happened. */
  when: string
  /** Where it happened. */
  where: string
  /** Why it happened, as evidenced. */
  why: string
  /** How it happened, as evidenced. */
  how: string
}

declare module '@deepseek-ai/dsh-session/types' {
  interface SessionEventMap {
    /**
     * One unique labeled identity harvested from a tool result. Duplicate
     * kind+value pairs are not appended; fold in log order.
     */
    'investigation/identity': Identity
    /**
     * One issued hunt. Duplicate kind+subject pairs are not appended; fold in
     * log order. Kerberos CNameString hunts follow a new IP or hostname; SAMR
     * QueryUserInfo hunts follow a new user.
     */
    'investigation/hunt': Hunt
    /**
     * Whole-value 5W1H case-close packet. The last `investigation/report` wins.
     */
    'investigation/report': CaseReport
  }
}
