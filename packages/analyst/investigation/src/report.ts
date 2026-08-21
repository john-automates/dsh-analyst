/**
 * Bind case_report who/where to a C2-talking LAN identity.
 * @module @deepseek-ai/dsh-investigation/report
 */

import { normalizeIdentityValue } from './harvest.ts'
import { c2TalkingLanIps, isLanIpv4, isNonLanUnicastIpv4 } from './hunts.ts'
import type { CaseReport, Identity } from './types.ts'

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
const MAC = /(?<![0-9a-fA-F]:)(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![:-][0-9a-fA-F]{2})/g

/** C2-talking LAN IP and, when unique on the ledger, its sourced eth.src MAC. */
export interface C2TalkingLanVictim {
  /** First-seen C2-talking LAN IPv4. */
  ip: string
  /** Unique ledger MAC treated as eth.src sourced from {@link C2TalkingLanVictim.ip}. */
  mac?: string
}

/**
 * Resolve the infected-host LAN identity used to bind who/where.
 * `c2TalkingLanIps` wins when it has a focus IP. Otherwise a unique ledger LAN
 * IP that shares the ledger with a non-LAN unicast IP is the focus.
 * A MAC is returned only when the ledger has exactly one MAC; names are never
 * resolved here.
 * @param identities - folded ledger identities.
 * @param evidenceText - current and prior tool-result text.
 * @returns the focus LAN IP and optional sourced MAC, or undefined when none is known.
 */
export function c2TalkingLanVictim(
  identities: readonly Identity[],
  evidenceText = '',
): C2TalkingLanVictim | undefined {
  let focus = c2TalkingLanIps(evidenceText)
  if (focus.length === 0) {
    const lanIps: string[] = []
    let hasC2 = false
    for (const identity of identities) {
      if (identity.kind !== 'ip') continue
      if (isNonLanUnicastIpv4(identity.value)) hasC2 = true
      else if (isLanIpv4(identity.value)) lanIps.push(identity.value)
    }
    const only = lanIps.length === 1 ? lanIps[0] : undefined
    if (hasC2 && only !== undefined) focus = [only]
  }
  const ip = focus[0]
  if (ip === undefined) return undefined
  const macs = identities.filter(identity => identity.kind === 'mac').map(identity => identity.value)
  const mac = macs.length === 1 ? macs[0] : undefined
  return mac === undefined ? { ip } : { ip, mac }
}

/**
 * Rewrite one who/where field onto the C2-talking LAN identity.
 * A non-LAN unicast IP is replaced only when the field does not already contain
 * the focus LAN IP. A MAC other than the sourced eth.src is replaced only when
 * that sourced MAC is known and the field does not already contain it.
 * Other LAN IPs, names, and non-address text are left as written.
 * @param text - trimmed who or where field.
 * @param victim - focus LAN IP and optional sourced MAC.
 * @returns the field with inverted C2 address tokens rewritten, or the original text.
 */
function rewriteHostField(text: string, victim: C2TalkingLanVictim): string {
  let out = text
  const ips = [...text.matchAll(new RegExp(IPV4.source, 'g'))].map(match => match[0])
  if (!ips.includes(victim.ip)) {
    out = out.replace(new RegExp(IPV4.source, 'g'), ip => (isNonLanUnicastIpv4(ip) ? victim.ip : ip))
  }
  if (victim.mac !== undefined) {
    const macs = [...out.matchAll(new RegExp(MAC.source, 'g'))]
    const hasSourced = macs.some(match => normalizeIdentityValue('mac', match[0]) === victim.mac)
    if (!hasSourced && macs.length > 0) {
      out = out.replace(new RegExp(MAC.source, 'g'), victim.mac)
    }
  }
  return out
}

/**
 * Bind case_report who/where to the C2-talking LAN IP and its sourced eth.src MAC.
 * what, when, why, and how are unchanged. Hostname, user, and full_name are not
 * inserted. With no focus IP the report is returned as given.
 * @param report - trimmed 5W1H packet from case_report.
 * @param identities - folded ledger identities.
 * @param evidenceText - current and prior tool-result text used by `c2TalkingLanIps`.
 * @returns the same report, or a copy whose who/where no longer name a C2 host.
 */
export function bindCaseReportToC2TalkingLan(
  report: CaseReport,
  identities: readonly Identity[],
  evidenceText = '',
): CaseReport {
  const victim = c2TalkingLanVictim(identities, evidenceText)
  if (victim === undefined) return report
  const who = rewriteHostField(report.who, victim)
  const where = rewriteHostField(report.where, victim)
  if (who === report.who && where === report.where) return report
  return { ...report, who, where }
}
