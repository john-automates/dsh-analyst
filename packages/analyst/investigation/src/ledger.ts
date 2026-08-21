/**
 * Prompt-facing investigation ledger, including the BindRelationship roles card.
 * @module @deepseek-ai/dsh-investigation/ledger
 */

import { formatRolesCard, roleForIdentity } from './bind.ts'
import type { CaseReport, Hunt, Identity, RelationshipBind } from './types.ts'

/**
 * Render the identity ledger, conversation bind, and open hunts.
 * When a live bind exists, identities are labeled with their endpoint role.
 * @param identities - folded identities.
 * @param hunts - folded hunts.
 * @param report - latest 5W1H report, when present.
 * @param bind - latest conversation bind, when present.
 * @returns ledger text, or empty when the ledger has nothing to show.
 */
export function formatLedger(
  identities: readonly Identity[],
  hunts: readonly Hunt[],
  report: CaseReport | { who: unknown } | undefined,
  bind?: RelationshipBind,
): string {
  if (identities.length === 0 && hunts.length === 0 && report === undefined && bind === undefined) {
    return ''
  }
  const lines = ['Investigation ledger']
  if (bind !== undefined) lines.push(formatRolesCard(bind))
  if (identities.length > 0) {
    lines.push('Identities:')
    for (const identity of identities) {
      const role = bind === undefined ? undefined : roleForIdentity(identity, bind, identities)
      lines.push(role === undefined
        ? `- ${identity.label} ${identity.value}`
        : `- [${role}] ${identity.label} ${identity.value}`)
    }
  }
  if (hunts.length > 0) {
    lines.push('Hunts:')
    for (const hunt of hunts) lines.push(`- ${hunt.kind} for ${hunt.subjectKind} ${hunt.subject}`)
  }
  if (report !== undefined) lines.push('A case_report 5W1H packet is already on this session log.')
  return lines.join('\n')
}
