/**
 * Investigation ledger types: the one home of the identity, hunt,
 * relationship-bind, and 5W1H report records persisted on the session log.
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
  /**
   * Endpoint this identity belongs to, when known. An identity whose
   * `entity_id` is a non-victim endpoint cannot donate who/where slots.
   */
  entity_id?: string
  /**
   * Conversation or entity this identity was taken from. A MAC stamps the
   * talking IPv4 that sources that eth.src, or hunt-subject IPv4 from a
   * field-only `eth.src` dump with no talking IP. A user or full_name stamps
   * the conversation client IPv4 (LAN / non-DC end), including a field-only
   * SAMR/CName dump whose evidence text names that client talking to a DC.
   * A `name-service` hunt-subject IPv4 scopes a hostname. An IP stamps
   * hunt-subject `scopeIp` when that scope is set. A slot whose
   * `evidence_id` points at a non-victim entity cannot donate who/where,
   * except a MAC later sourced from the bound victim IP or restamped from a
   * victim-IP-scoped `eth.src` dump — including overwrite of a DC/peer first
   * stamp — or a user or full_name whose conversation `ip.src` is that
   * victim.
   */
  evidence_id?: string
}

/** Candidate labels a Plan hypothesis may assign. */
export type CandidateLabel = 'victim' | 'c2' | 'dc' | 'cdn' | 'update' | 'distractor'

/** Slot 0a: whether the cue/observation is even a valid observation. */
export type CueValidation = 'valid' | 'open' | 'invalid'

/** Thesis-revise scenario object. Not a fourth IR phase. */
export interface ThesisRevise {
  /** Scenario name. */
  name: string
  /** Claim under test. */
  claim: string
  /** Disconfirm rule. */
  rule: string
  /** Outcome of that rule. */
  result: 'confirm' | 'kill' | 'gap'
}

/** Mission persist: purpose, cue, slot 0a, scored slots, closed-means. */
export interface InvestigationMission {
  /** Why this case is being investigated. Chassis stamps a victim-identity + C2 purpose. */
  purpose: string
  /**
   * Scored or named slots, including `0a` for validate-the-cue.
   * The plugin stamps Mission at session start to scope the case.
   * Auto-hunts run after Plan is ready. The model cannot overwrite purpose.
   */
  slots: Record<string, { score?: number; value?: string }>
  /** Closed investigative means for this case. */
  closedMeans: string[]
  /** Cue/observation pointer. */
  cue: { addr: string; evidence_id: string }
  /** Slot 0a: cue validated, explicitly open, or invalid. */
  cueValidation: CueValidation
}

/** One Plan hypothesis: `I believe X because Y` plus a disconfirm test. */
export interface InvestigationHypothesis {
  /** Opaque hypothesis id. Action rows cite this id. */
  id: string
  /** Claim in the form `I believe X because Y`. */
  claim: string
  /** How this hypothesis would be killed. */
  disconfirm: string
  /** Candidate role label. */
  label: CandidateLabel
}

/**
 * One append-only Plan entry. Later entries add inventory, gaps, or
 * hypotheses. They do not replace earlier ones.
 */
export interface InvestigationPlanEntry {
  /** Sources that can attest, when this entry adds inventory. */
  inventory?: string[]
  /** Known gaps, when this entry adds gaps. */
  gaps?: string[]
  /** Hypotheses appended by this entry. */
  hypotheses?: InvestigationHypothesis[]
}

/** Folded Plan: concatenated inventory, gaps, and first-seen hypotheses. */
export interface InvestigationPlan {
  /** Sources that can attest. */
  inventory: string[]
  /** Open gaps. */
  gaps: string[]
  /** Hypotheses in first-seen id order. */
  hypotheses: InvestigationHypothesis[]
}

/**
 * Action persist: one hunt outcome pointing at a Plan hypothesis.
 * BindRelationship is an answer artifact, not a substitute for naming the C2 H.
 */
export interface InvestigationAction {
  /** Hunt kind that ran. */
  huntKind: HuntKind
  /** Hunt subject. */
  subject: string
  /** Plan hypothesis this hunt tests. */
  hypothesis_id: string
  /** Evidence pointer, when one exists. */
  evidence_id?: string
  /** Thesis-revise scenario for this hunt. */
  thesis: ThesisRevise
}

/**
 * Report-hook extras: leftover C2 IPs and domain from proven hunts.
 * Not an accepted close. Who/where are not invented.
 */
export interface CaseReportExtras {
  /**
   * Bound C2 IPv4 plus dests that evidence the accepted non-CDN
   * `c2_domain`, omitting CDN/update names, published Cloudflare
   * anycast dests, and leftover unnamed extras. Omitted when none remain.
   */
  c2_ips?: string[]
  /**
   * First non-CDN dotted name evidenced on an attested dest.
   * Omitted when none was harvested.
   */
  c2_domain?: string
  /** Hypothesis ids whose Action thesis result is kill. */
  killed?: string[]
}

/** Auto-issued or recorded hunt kinds. */
export type HuntKind =
  | 'kerberos-cname'
  | 'samr-userinfo'
  | 'eth-src'
  | 'name-service'
  | 'other-end'
  | 'c2-domain'
  | 'extra-wan'

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

/** Roles a bound conversation endpoint may hold. */
export type EndpointRole = 'victim' | 'c2' | 'infra' | 'distractor' | 'unknown'

/** Cited two-endpoint conversation that BindRelationship assigns roles on. */
export interface Relationship {
  /** Conversation source address. */
  src: string
  /** Conversation destination address. */
  dst: string
  /** Destination port. */
  dport: number
  /** Conversation time as submitted. */
  t: string
  /** Id of the cited conversation evidence. */
  evidence_id: string
}

/** One endpoint after BindRelationship assigns a role. */
export interface BoundEndpoint {
  /** Endpoint address. */
  addr: string
  /** Assigned role. Cue/observation addresses default to `c2`. */
  role: EndpointRole
  /** Why this role was assigned. */
  because: string
}

/** Live conversation bind stored on `investigation/bind`. */
export interface RelationshipBind {
  /** Cited conversation. */
  relationship: Relationship
  /** Endpoints with roles. Exactly one must be `victim`. */
  endpoints: BoundEndpoint[]
}

/** Projected who/where slot: the victim entity row, not free text. */
export interface CaseIdentitySlot {
  /** Bound victim entity id (the victim endpoint address). */
  entity_id: string
  /** Victim IPv4, when known. */
  ip?: string
  /** Victim MAC, when it belongs to the victim entity. */
  mac?: string
  /** Victim hostname, when it belongs to the victim entity. */
  hostname?: string
  /** Victim user, when it belongs to the victim entity. */
  user?: string
  /** Victim full name, when it belongs to the victim entity. */
  full_name?: string
}

/** 5W1H case-close packet stored on `investigation/report`. */
export interface CaseReport {
  /** Victim entity row projected into who. */
  who: CaseIdentitySlot
  /** What happened. */
  what: string
  /** When it happened. */
  when: string
  /** Victim entity row projected into where. */
  where: CaseIdentitySlot
  /** Why it happened, as evidenced. */
  why: string
  /** How it happened, as evidenced. */
  how: string
  /**
   * Bound C2 IPv4 plus dests that evidence the accepted non-CDN
   * `c2_domain`, omitting an IP in a published Cloudflare anycast
   * prefix, whose evidenced hostname is a well-known CDN or update
   * name, or a leftover unnamed extra. Omitted when none remain. Not a
   * who/where slot and not a second bind.
   */
  c2_ips?: string[]
  /**
   * TLS SNI or DNS name evidenced on an attested dest (bound C2 or a
   * dest that evidences that name) that is not a well-known CDN or
   * update name. Omitted when none was harvested. Not a who/where
   * hostname and not a victim-row donate.
   */
  c2_domain?: string
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
     * log order. A new IP issues `eth-src`, `name-service`, Kerberos
     * CNameString, and SAMR QueryUserInfo. After a LAN IP talks to a non-LAN
     * peer, those identity hunts issue only for that C2-talking IP. Assigning
     * victim to a cue/observation address issues `other-end` for that cue IP
     * (`ip.dst ==` the cue, field `ip.src`). A successful bind with a unique
     * LAN victim and unique non-LAN C2 that is not a well-known CDN or
     * update destination issues `extra-wan` for that victim
     * (`ip.src ==` the victim, field `ip.dst`) and `c2-domain` for each
     * remaining C2 IPv4 (bound plus harvested extras; TLS SNI / DNS). A
     * both-LAN or CDN/update C2 deny does not issue `other-end`,
     * `extra-wan`, or `c2-domain` and does not invent a C2. When `autoHunt`
     * is true and Plan is ready, outstanding issued hunts execute through
     * `pcap_filter` with the scoped display filter; `other-end` and
     * `c2-domain` auto-run even though the subject is the cue or C2, and
     * `extra-wan` auto-runs for the LAN victim even when a C2-talking
     * focus IP exists. Mission alone does not auto-run. A new hostname
     * issues Kerberos then SAMR. A new user issues SAMR.
     */
    'investigation/hunt': Hunt
    /**
     * Live conversation bind. The last `investigation/bind` wins. case_report
     * is denied until this event exists with exactly one victim.
     */
    'investigation/bind': RelationshipBind
    /**
     * Whole-value 5W1H case-close packet. The last `investigation/report` wins.
     * who/where are the projected victim entity row; omitted model keys are
     * filled from that row after deny/coerce. Omitted who/where also fold
     * sibling top-level identity keys (ip, mac, hostname, user, full_name)
     * from the same case_report arguments into that submitted slot. Omitted
     * mac persists the unique ledger MAC that is not DC/gateway-only when a
     * sticky DC donate or uniqueness left the row empty. Omitted user still
     * persists from victim-IP evidence. A submitted user, hostname, or
     * full_name is kept when the row has no donated value and that identity
     * does not donate to a different entity. A submitted human user is kept
     * without a conversation-client stamp. A machine SAM ending in `$` is
     * not persisted as user. A submitted mac is kept unless talking-IP frames
     * source that MAC only from a non-victim. `c2_ips` is the bound C2 IPv4
     * plus dests that evidence the accepted non-CDN `c2_domain`, omitting
     * an IP in a published Cloudflare anycast prefix, whose evidenced
     * hostname is a well-known CDN or update name, or a leftover unnamed
     * extra, when any remain. `c2_domain` is the harvested TLS SNI or DNS
     * name evidenced on an attested dest that is not CDN/update, when one
     * exists.
     */
    'investigation/report': CaseReport
    /**
     * Mission persist. The last `investigation/mission` wins. The plugin
     * stamps Mission at session start as a victim-identity + C2
     * investigation. Mission scopes the case. Auto-hunts run after Plan
     * is ready. Bind still needs a named C2 hypothesis on the Plan.
     */
    'investigation/mission': InvestigationMission
    /**
     * One append-only Plan entry. Fold concatenates inventory, gaps, and
     * first-seen hypotheses. Answers generate more questions.
     */
    'investigation/plan': InvestigationPlanEntry
    /**
     * One Action hunt outcome. Every auto-run hunt row carries
     * `hypothesis_id`, including identity hunts. BindRelationship is not
     * a substitute for naming the C2 H.
     */
    'investigation/action': InvestigationAction
    /**
     * Report-hook leftover extras. The last `investigation/extras` wins for
     * fields it sets. Not an accepted close: who/where/what/when/why/how are
     * absent. `foldReport` overlays these extras onto a later 5W1H packet.
     * A denied prose `case_report` does not wipe this event.
     */
    'investigation/extras': CaseReportExtras
  }
}
