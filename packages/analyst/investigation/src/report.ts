/**
 * C2-talking LAN focus helper. BindRelationship uses this to affiliate a
 * sourced eth.src MAC with the bound victim. It does not rewrite who/where.
 * @module @deepseek-ai/dsh-investigation/report
 */

import { c2TalkingLanIps, isLanIpv4, isNonLanUnicastIpv4 } from './hunts.ts'
import type { Identity } from './types.ts'

/** C2-talking LAN IP and, when unique on the ledger, its sourced eth.src MAC. */
export interface C2TalkingLanVictim {
  /** First-seen C2-talking LAN IPv4. */
  ip: string
  /** Unique ledger MAC treated as eth.src sourced from {@link C2TalkingLanVictim.ip}. */
  mac?: string
}

/**
 * Resolve the C2-talking LAN IP used as a BindRelationship helper.
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
