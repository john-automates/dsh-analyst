/**
 * Analyst Mindset chassis: Mission / Plan / Action / Report wrap DINQ
 * (Observation → Question → Hypothesis → Answer → Bind → Who/Where).
 * Thesis-revise is a scenario object, not a fourth IR phase.
 * The plugin stamps Mission at session start to scope the case.
 * Auto-hunts run only when Plan is ready. Bind needs a named C2 hypothesis.
 *
 * @module @deepseek-ai/dsh-investigation/mindset
 */

import type { SessionEvent } from '@deepseek-ai/dsh-session'
import { acceptedC2Domain, acceptedC2Ips } from './bind.ts'
import type {
  CaseReport, CaseReportExtras, Hunt, HuntKind, Identity, InvestigationAction,
  InvestigationHypothesis, InvestigationMission, InvestigationPlan,
  InvestigationPlanEntry, RelationshipBind, ThesisRevise,
} from './types.ts'

/** Chassis Mission purpose. The model cannot overwrite this into a different purpose. */
export const CHASSIS_MISSION_PURPOSE = 'This is a victim-identity + C2 investigation.'

/** Chassis closed-means. Who/where stay victim-only. C2 is not CDN/DC/update. Extras only if proven. */
export const CHASSIS_CLOSED_MEANS = [
  'who/where proven on the victim',
  'C2 is not CDN/DC/update',
  'extras only if proven',
] as const

/** Pending cue pointer until slot 0a names a real observation. */
export const CHASSIS_CUE_PENDING = { addr: 'cue-pending', evidence_id: 'chassis' } as const

/** Deny text when bind has no named C2 hypothesis on the Plan. */
export const PLAN_C2_HYPOTHESIS_REASON =
  'unbound: name a C2 hypothesis on the Plan before bind_relationship.'

/** Deny text when bind has no CDN/DC/update alternative on the Plan. */
export const PLAN_ALTERNATIVE_REASON =
  'unbound: check CDN/DC alternatives on the Plan before bind_relationship.'

/** Deny text when bind has no source inventory on the Plan. */
export const PLAN_INVENTORY_REASON =
  'unbound: inventory what can attest on the Plan before bind_relationship.'

/** Deny text when slot 0a marked the cue invalid. */
export const CUE_INVALID_REASON =
  'unbound: slot 0a cueValidation is invalid; validate the cue before bind_relationship.'

/** Deny text when slot 0a is still the chassis pending cue. */
export const CUE_PENDING_REASON =
  'unbound: slot 0a must name a real cue (valid or explicitly open) before bind_relationship.'

/** Alias of {@link PLAN_C2_HYPOTHESIS_REASON}. */
export const PLAN_NOT_READY_REASON = PLAN_C2_HYPOTHESIS_REASON

/** Labels that count as a CDN / DC / update alternative hypothesis. */
const ALTERNATIVE_LABELS = new Set(['dc', 'cdn', 'update'])

/**
 * Open CDN-or-update alternative persisted when Plan omits one after a
 * named live cue. A submitted alternative is kept.
 * @returns a claim in the required `I believe X because Y` form.
 */
export function defaultOpenAlternative(): InvestigationHypothesis {
  return {
    id: 'h-alt',
    claim:
      'I believe a CDN or update alternative is still open because a well-known CDN or update dest has not been ruled out',
    disconfirm: 'a non-CDN dotted name is evidenced on that dest',
    label: 'cdn',
  }
}

/**
 * Whether any hypothesis is a CDN / DC / update alternative.
 * @param hypotheses - Plan hypotheses or one entry's list.
 * @returns true when at least one label is `dc`, `cdn`, or `update`.
 */
export function hasAlternativeHypothesis(
  hypotheses: readonly InvestigationHypothesis[],
): boolean {
  return hypotheses.some(item => ALTERNATIVE_LABELS.has(item.label))
}

/** Claim form required on every Plan hypothesis. */
const BELIEVE_BECAUSE = /^I believe .+ because .+/

/**
 * Fold the last Mission from a log prefix.
 * @param events - session log or any prefix of it.
 * @returns the last Mission, or undefined when none exists.
 */
export function foldMission(events: readonly SessionEvent[]): InvestigationMission | undefined {
  let mission: InvestigationMission | undefined
  for (const event of events) {
    if (event.type === 'investigation/mission') mission = event.data
  }
  return mission
}

/**
 * Fold append-only Plan entries. Inventory and gaps concatenate uniquely.
 * First-seen hypothesis id wins; later entries add new questions.
 * @param events - session log or any prefix of it.
 * @returns concatenated Plan.
 */
export function foldPlan(events: readonly SessionEvent[]): InvestigationPlan {
  const inventory: string[] = []
  const gaps: string[] = []
  const hypotheses: InvestigationHypothesis[] = []
  const seenInventory = new Set<string>()
  const seenGaps = new Set<string>()
  const seenH = new Set<string>()
  for (const event of events) {
    if (event.type !== 'investigation/plan') continue
    appendUnique(event.data.inventory, inventory, seenInventory)
    appendUnique(event.data.gaps, gaps, seenGaps)
    for (const hypothesis of event.data.hypotheses ?? []) {
      if (seenH.has(hypothesis.id)) continue
      seenH.add(hypothesis.id)
      hypotheses.push(hypothesis)
    }
  }
  return { inventory, gaps, hypotheses }
}

/**
 * Fold Action rows in log order.
 * @param events - session log or any prefix of it.
 * @returns Action rows.
 */
export function foldActions(events: readonly SessionEvent[]): InvestigationAction[] {
  const out: InvestigationAction[] = []
  for (const event of events) {
    if (event.type === 'investigation/action') out.push(event.data)
  }
  return out
}

/**
 * Fold leftover extras from extras events and from 5W1H packets.
 * An extras event does not invent who/where. A later report that omits
 * a field keeps the extras-event value. A denied case_report writes nothing.
 * @param events - session log or any prefix of it.
 * @returns folded extras, or undefined when none exist.
 */
export function foldExtras(events: readonly SessionEvent[]): CaseReportExtras | undefined {
  let extras: CaseReportExtras | undefined
  for (const event of events) {
    if (event.type === 'investigation/extras') {
      extras = mergeExtras(extras, event.data)
      continue
    }
    if (event.type === 'investigation/report') {
      extras = mergeExtras(extras, extrasFromReport(event.data))
    }
  }
  return emptyExtras(extras) ? undefined : extras
}

/**
 * Overlay leftover extras onto an accepted 5W1H packet.
 * Keeps who/what/when/where/why/how. Unions `c2_ips`. Fills omitted `c2_domain`.
 * @param report - last accepted close packet.
 * @param extras - folded extras, when present.
 * @returns the report with extras applied.
 */
export function applyHuntExtras(report: CaseReport, extras?: CaseReportExtras): CaseReport {
  if (extras === undefined) return report
  const ips = uniqueIps([...(report.c2_ips ?? []), ...(extras.c2_ips ?? [])])
  const domain = report.c2_domain ?? extras.c2_domain
  const next: CaseReport = { ...report }
  if (ips.length > 0) next.c2_ips = ips
  if (domain !== undefined) next.c2_domain = domain
  return next
}

/**
 * Compute Report-hook extras from a live bind and harvested identities.
 * CDN/update dests and leftover unnamed extras stay off `c2_ips`.
 * First non-CDN dotted name on an attested dest wins `c2_domain`.
 * LAN / DC / gateway stay off. Does not invent 5W1H.
 * @param bind - live bind.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text for cited-conversation SNI / host / DNS.
 * @param killed - hypothesis ids killed by Action thesis rows.
 * @returns extras when any field is present.
 */
export function projectHuntExtras(
  bind: RelationshipBind,
  identities: readonly Identity[],
  evidenceText = '',
  killed: readonly string[] = [],
): CaseReportExtras | undefined {
  const extras: CaseReportExtras = {}
  const ips = acceptedC2Ips(bind, identities, evidenceText)
  if (ips.length > 0) extras.c2_ips = ips
  const domain = acceptedC2Domain(bind, identities, evidenceText)
  if (domain !== undefined) extras.c2_domain = domain
  if (killed.length > 0) extras.killed = [...killed]
  return emptyExtras(extras) ? undefined : extras
}

/**
 * Whether leftover extras already match what the hunts produced.
 * @param existing - extras already folded from the log.
 * @param next - extras computed from the current hunts.
 * @returns true when persist would write the same fields.
 */
export function sameHuntExtras(
  existing: CaseReportExtras | undefined,
  next: CaseReportExtras,
): boolean {
  if (existing === undefined) return false
  return JSON.stringify(normalizeExtras(existing)) === JSON.stringify(normalizeExtras(next))
}

/**
 * Chassis Mission stamped at session start. Scopes the case only.
 * cueValidation `open` here is pending until investigation_mission names
 * a real cue. That pending cue does not unlock auto-hunts or bind.
 * @returns the chassis Mission (cue pending, slot 0a open).
 */
export function chassisMission(): InvestigationMission {
  return {
    purpose: CHASSIS_MISSION_PURPOSE,
    slots: { '0a': { value: 'open' } },
    closedMeans: [...CHASSIS_CLOSED_MEANS],
    cue: { addr: CHASSIS_CUE_PENDING.addr, evidence_id: CHASSIS_CUE_PENDING.evidence_id },
    cueValidation: 'open',
  }
}

/**
 * Whether Plan is ready for any auto-run and for a successful bind.
 * Requires a named cue (`valid` or explicitly `open`, not cue-pending),
 * at least one C2 hypothesis, at least one CDN/DC/update alternative,
 * and an inventory of what can attest. Cue `invalid` blocks. Mission
 * alone is never enough. Chassis cue-pending is not a validated observation.
 * @param mission - last Mission, or undefined.
 * @param plan - folded Plan.
 * @returns true when auto-hunts and bind success may proceed.
 */
export function planReady(
  mission: InvestigationMission | undefined,
  plan: InvestigationPlan,
): boolean {
  return planReadyDenyReason(mission, plan) === undefined
}

/**
 * Deny reason when a resolved bind may not be recorded and auto-hunts
 * must stay off.
 * @param mission - last Mission, or undefined.
 * @param plan - folded Plan.
 * @returns a bind deny reason, or undefined when bind and auto-run may proceed.
 */
export function planReadyDenyReason(
  mission: InvestigationMission | undefined,
  plan: InvestigationPlan,
): string | undefined {
  const cueDeny = cueSlotDenyReason(mission)
  if (cueDeny !== undefined) return cueDeny
  if (!plan.hypotheses.some(item => item.label === 'c2')) return PLAN_C2_HYPOTHESIS_REASON
  if (!hasAlternativeHypothesis(plan.hypotheses)) return PLAN_ALTERNATIVE_REASON
  if (plan.inventory.length === 0) return PLAN_INVENTORY_REASON
  return undefined
}

/**
 * Whether slot 0a names a real cue that is `valid` or explicitly `open`.
 * Chassis cue-pending and cueValidation `invalid` are not live.
 * @param mission - last Mission, or undefined.
 * @returns true when a named live cue is on the Mission.
 */
export function namedLiveCue(mission: InvestigationMission | undefined): boolean {
  return cueSlotDenyReason(mission) === undefined
}

/**
 * Deny reason when slot 0a is not a named, valid-or-open cue.
 * @param mission - last Mission, or undefined.
 * @returns a cue deny reason, or undefined when the cue slot is ready.
 */
function cueSlotDenyReason(mission: InvestigationMission | undefined): string | undefined {
  if (mission?.cueValidation === 'invalid') return CUE_INVALID_REASON
  if (
    mission === undefined
    || (mission.cueValidation !== 'valid' && mission.cueValidation !== 'open')
    || mission.cue.addr === CHASSIS_CUE_PENDING.addr
    || mission.cue.addr.trim() === ''
  ) {
    return CUE_PENDING_REASON
  }
  return undefined
}

/**
 * First C2 hypothesis id on the folded Plan.
 * @param plan - folded Plan.
 * @returns that id, or undefined when none exists.
 */
export function c2HypothesisId(plan: InvestigationPlan): string | undefined {
  return plan.hypotheses.find(item => item.label === 'c2')?.id
}

/**
 * C2 hypothesis id required on an Action row that tests C2.
 * @param plan - folded Plan.
 * @returns that id.
 * @throws when Plan has no C2 hypothesis.
 */
export function requireC2HypothesisId(plan: InvestigationPlan): string {
  const id = c2HypothesisId(plan)
  if (id === undefined) throw new Error('Action requires a named C2 hypothesis')
  return id
}

/**
 * Hypothesis id an Action row cites for one auto-run hunt.
 * Identity hunts cite the first victim hypothesis when one exists,
 * otherwise the first C2 hypothesis. leftover and other-end cite C2.
 * @param hunt - hunt that ran.
 * @param plan - folded Plan (must be ready).
 * @returns that id.
 */
export function hypothesisIdForHunt(hunt: Hunt, plan: InvestigationPlan): string {
  if (
    hunt.kind === 'eth-src'
    || hunt.kind === 'name-service'
    || hunt.kind === 'kerberos-cname'
    || hunt.kind === 'samr-userinfo'
  ) {
    const victim = plan.hypotheses.find(item => item.label === 'victim')?.id
    if (victim !== undefined) return victim
  }
  return requireC2HypothesisId(plan)
}

/**
 * Whether one Plan hypothesis claim has the required form.
 * @param claim - hypothesis claim.
 * @returns true when the claim is `I believe X because Y`.
 */
export function isBelieveBecauseClaim(claim: string): boolean {
  return BELIEVE_BECAUSE.test(claim)
}

/**
 * Validate one Plan entry before persist.
 * @param entry - candidate Plan entry.
 * @returns a deny reason, or undefined when the entry may append.
 */
export function planEntryDenyReason(entry: InvestigationPlanEntry): string | undefined {
  const hasInventory = (entry.inventory?.length ?? 0) > 0
  const hasGaps = (entry.gaps?.length ?? 0) > 0
  const hypotheses = entry.hypotheses ?? []
  if (!hasInventory && !hasGaps && hypotheses.length === 0) {
    return 'investigation_plan requires inventory, gaps, or a hypothesis'
  }
  for (const hypothesis of hypotheses) {
    if (hypothesis.id.trim() === '') return 'investigation_plan hypothesis id must be a non-empty string'
    if (!isBelieveBecauseClaim(hypothesis.claim)) {
      return 'investigation_plan hypothesis claim must be "I believe X because Y"'
    }
    if (hypothesis.disconfirm.trim() === '') {
      return 'investigation_plan hypothesis disconfirm must be a non-empty string'
    }
  }
  return undefined
}

/**
 * Build one Action row for an extra-wan or c2-domain hunt dump.
 * @param hunt - issued hunt that just ran.
 * @param hypothesisId - Plan C2 hypothesis id.
 * @param thesis - thesis-revise outcome for that dump.
 * @param evidenceId - evidence pointer, when one exists.
 * @returns the Action row.
 */
export function actionForHunt(
  hunt: Hunt,
  hypothesisId: string,
  thesis: ThesisRevise,
  evidenceId?: string,
): InvestigationAction {
  const action: InvestigationAction = {
    huntKind: hunt.kind,
    subject: hunt.subject,
    hypothesis_id: hypothesisId,
    thesis,
  }
  if (evidenceId !== undefined) action.evidence_id = evidenceId
  return action
}

/**
 * Thesis-revise outcome for one auto-run hunt dump.
 * Leftover extra-wan / c2-domain use leftover confirm/kill wording.
 * Identity and other-end hunts confirm on a harvested value.
 * @param huntKind - hunt that ran.
 * @param confirm - whether the dump harvested a proving value.
 * @param killed - whether a leftover dump evidenced only CDN/update.
 * @returns the scenario object.
 */
export function thesisForHuntDump(
  huntKind: HuntKind,
  confirm: boolean,
  killed: boolean,
): ThesisRevise {
  if (huntKind === 'extra-wan' || huntKind === 'c2-domain') {
    if (confirm) {
      return {
        name: huntKind,
        claim: `I believe ${huntKind} produced a leftover C2 because the dump harvested a non-CDN dest or name`,
        rule: 'non-CDN leftover on a remaining C2 IP',
        result: 'confirm',
      }
    }
    if (killed) {
      return {
        name: huntKind,
        claim: `I believe ${huntKind} produced only CDN/update because the dump named a well-known update or CDN dest`,
        rule: 'CDN/update dests stay off leftovers',
        result: 'kill',
      }
    }
    return {
      name: huntKind,
      claim: `I believe ${huntKind} is still open because the dump harvested no leftover`,
      rule: 'empty dump is a gap',
      result: 'gap',
    }
  }
  if (confirm) {
    return {
      name: huntKind,
      claim: `I believe ${huntKind} produced an identity because the dump harvested a value`,
      rule: 'harvested identity on this hunt',
      result: 'confirm',
    }
  }
  return {
    name: huntKind,
    claim: `I believe ${huntKind} is still open because the dump harvested no identity`,
    rule: 'empty dump is a gap',
    result: 'gap',
  }
}

/**
 * Killed hypothesis ids from Action rows.
 * @param actions - folded Action rows.
 * @returns unique ids whose thesis result is kill.
 */
export function killedHypothesisIds(actions: readonly InvestigationAction[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const action of actions) {
    if (action.thesis.result !== 'kill') continue
    if (seen.has(action.hypothesis_id)) continue
    seen.add(action.hypothesis_id)
    out.push(action.hypothesis_id)
  }
  return out
}

function appendUnique(
  values: readonly string[] | undefined,
  out: string[],
  seen: Set<string>,
): void {
  if (values === undefined) return
  for (const value of values) {
    if (seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
}

function extrasFromReport(report: CaseReport): CaseReportExtras | undefined {
  const extras: CaseReportExtras = {}
  if (report.c2_ips !== undefined) extras.c2_ips = report.c2_ips
  if (report.c2_domain !== undefined) extras.c2_domain = report.c2_domain
  return emptyExtras(extras) ? undefined : extras
}

function mergeExtras(
  base: CaseReportExtras | undefined,
  overlay: CaseReportExtras | undefined,
): CaseReportExtras | undefined {
  if (overlay === undefined) return base
  if (base === undefined) return overlay
  const next: CaseReportExtras = { ...base }
  if (overlay.c2_ips !== undefined) next.c2_ips = overlay.c2_ips
  if (overlay.c2_domain !== undefined) next.c2_domain = overlay.c2_domain
  if (overlay.killed !== undefined) next.killed = overlay.killed
  return next
}

function emptyExtras(extras: CaseReportExtras | undefined): extras is undefined {
  if (extras === undefined) return true
  return extras.c2_ips === undefined && extras.c2_domain === undefined && extras.killed === undefined
}

function uniqueIps(values: readonly string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const value of values) {
    if (seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

function normalizeExtras(extras: CaseReportExtras): CaseReportExtras {
  const next: CaseReportExtras = {}
  if (extras.c2_ips !== undefined) next.c2_ips = [...extras.c2_ips]
  if (extras.c2_domain !== undefined) next.c2_domain = extras.c2_domain
  if (extras.killed !== undefined) next.killed = [...extras.killed]
  return next
}
