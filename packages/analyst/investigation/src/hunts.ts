/**
 * Auto-issued hunt selection after newly recorded identities.
 * @module @deepseek-ai/dsh-investigation/hunts
 */

import type { Hunt, HuntKind, Identity } from './types.ts'

/** Uniqueness key for one hunt. */
export function huntKey(hunt: Hunt): string {
  return `${hunt.kind}\0${hunt.subjectKind}\0${hunt.subject}`
}

/**
 * Hunts to issue after identities that were just recorded.
 * A new IP or hostname issues `kerberos-cname`. A new user issues `samr-userinfo`.
 * @param added - identities appended on this tool result.
 * @param existing - hunts already on the session log.
 * @returns new hunts in issue order, unique against `existing` and themselves.
 */
export function huntsForNewIdentities(added: readonly Identity[], existing: readonly Hunt[]): Hunt[] {
  const seen = new Set(existing.map(huntKey))
  const out: Hunt[] = []
  const issue = (kind: HuntKind, identity: Identity): void => {
    const hunt: Hunt = {
      kind,
      subjectKind: identity.kind === 'user' ? 'user' : identity.kind === 'hostname' ? 'hostname' : 'ip',
      subject: identity.value,
    }
    const key = huntKey(hunt)
    if (seen.has(key)) return
    seen.add(key)
    out.push(hunt)
  }
  for (const identity of added) {
    if (identity.kind === 'ip' || identity.kind === 'hostname') issue('kerberos-cname', identity)
    if (identity.kind === 'user') issue('samr-userinfo', identity)
  }
  return out
}

/**
 * Model-facing notice for one issued hunt.
 * @param hunt - the hunt just appended.
 * @returns notice text naming the valid tshark 4.4.16 fields.
 */
export function huntNotice(hunt: Hunt): string {
  if (hunt.kind === 'kerberos-cname') {
    return [
      `Hunt issued: kerberos-cname for ${hunt.subjectKind} ${hunt.subject}.`,
      'Run pcap_filter with display_filter `kerberos.CNameString` and field `kerberos.CNameString`.',
      'Do not use kerberos.username, ldap.sAMAccountName, or ldap.displayName — those fields are invalid in tshark 4.4.16.',
      'After a username appears, hunt samr-userinfo with fields samr.samr_UserInfo21.account_name and samr.samr_UserInfo21.full_name (UTF-16 SAMR, not LDAP displayName).',
    ].join(' ')
  }
  return [
    `Hunt issued: samr-userinfo for ${hunt.subjectKind} ${hunt.subject}.`,
    'Run pcap_filter with display_filter `samr.samr_UserInfo21.account_name or samr.samr_UserInfo21.full_name`',
    'and fields `samr.samr_UserInfo21.account_name`, `samr.samr_UserInfo21.full_name`.',
    'SAMR full_name is UTF-16LE (Becka Rolf is the worked example), not ldap.displayName.',
  ].join(' ')
}

/**
 * Render the identity ledger and open hunts for the prompt context.
 * @param identities - folded identities.
 * @param hunts - folded hunts.
 * @param report - latest 5W1H report, when present.
 * @returns ledger text, or empty when the ledger has nothing to show.
 */
export function formatLedger(
  identities: readonly Identity[],
  hunts: readonly Hunt[],
  report: { who: string } | undefined,
): string {
  if (identities.length === 0 && hunts.length === 0 && report === undefined) return ''
  const lines = ['Investigation ledger']
  if (identities.length > 0) {
    lines.push('Identities:')
    for (const identity of identities) lines.push(`- ${identity.label} ${identity.value}`)
  }
  if (hunts.length > 0) {
    lines.push('Hunts:')
    for (const hunt of hunts) lines.push(`- ${hunt.kind} for ${hunt.subjectKind} ${hunt.subject}`)
  }
  if (report !== undefined) lines.push('A case_report 5W1H packet is already on this session log.')
  return lines.join('\n')
}
