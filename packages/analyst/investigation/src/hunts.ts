/**
 * Auto-issued hunt selection after newly recorded identities.
 * @module @deepseek-ai/dsh-investigation/hunts
 */

import { assertNever } from '@deepseek-ai/dsh-llm'
import type { SessionEvent } from '@deepseek-ai/dsh-session'
import type { Hunt, HuntKind, Identity } from './types.ts'

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
const SKIP_IPS = new Set(['0.0.0.0', '255.255.255.255'])

/**
 * Uniqueness key for one hunt.
 * @param hunt - hunt kind, subject kind, and subject.
 * @returns kind+subject key.
 */
export function huntKey(hunt: Hunt): string {
  return `${hunt.kind}\0${hunt.subjectKind}\0${hunt.subject}`
}

/**
 * Whether an IPv4 address is RFC1918 LAN space.
 * @param ip - dotted IPv4.
 * @returns true for 10/8, 172.16/12, and 192.168/16.
 */
export function isLanIpv4(ip: string): boolean {
  const parts = ip.split('.')
  const a = Number(parts[0])
  const b = Number(parts[1])
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}

/**
 * Whether an IPv4 address is a unicast non-LAN peer (external / C2).
 * Loopback, link-local, multicast, reserved, and broadcast are excluded.
 * @param ip - dotted IPv4.
 * @returns true for a unicast address outside RFC1918.
 */
export function isNonLanUnicastIpv4(ip: string): boolean {
  if (SKIP_IPS.has(ip)) return false
  const parts = ip.split('.')
  const a = Number(parts[0])
  const b = Number(parts[1])
  if (a === 127 || (a === 169 && b === 254) || a >= 224) return false
  return !isLanIpv4(ip)
}

/**
 * LAN IPv4s that share a tool-output line with a non-LAN unicast peer.
 * One line is one conversation; idle LAN-to-LAN or LAN-to-multicast lines do not qualify.
 * @param text - rendered tool output or concatenated prior tool-result text.
 * @returns unique C2-talking LAN IPs in first-seen order.
 */
export function c2TalkingLanIps(text: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const line of text.split(/\r?\n/)) {
    const ips = line.match(IPV4) ?? []
    if (ips.length < 2 || !ips.some(isNonLanUnicastIpv4)) continue
    for (const ip of ips) {
      if (!isLanIpv4(ip) || seen.has(ip)) continue
      seen.add(ip)
      out.push(ip)
    }
  }
  return out
}

/**
 * Concatenate text blocks from logged `tool/result` events.
 * @param events - session log or any prefix of it.
 * @returns joined tool-result text, or empty when none is present.
 */
export function foldToolResultText(events: readonly SessionEvent[]): string {
  const parts: string[] = []
  for (const event of events) {
    if (event.type !== 'tool/result') continue
    const block = event.data.message.content[0]
    if (block === undefined || block.type !== 'tool-result') continue
    for (const item of block.content) {
      if (item.type === 'text') parts.push(item.text)
    }
  }
  return parts.join('\n')
}

/**
 * Join prior tool-result text with the current result.
 * @param events - session log already holding earlier tool results.
 * @param current - text of the tool result being observed.
 * @returns concatenated evidence text for C2-talking detection.
 */
export function evidenceTextForHunts(events: readonly SessionEvent[], current: string): string {
  const prior = foldToolResultText(events)
  if (prior === '') return current
  if (current === '') return prior
  return `${prior}\n${current}`
}

/**
 * Hunts to issue after identities that were just recorded.
 * A new IP issues `eth-src`, `name-service`, `kerberos-cname`, then `samr-userinfo`.
 * A new hostname issues `kerberos-cname` then `samr-userinfo`.
 * A new user issues `samr-userinfo`. SAMR does not wait for a harvested user.
 * `name-service` is LLMNR/NBNS/BROWSER. SMB is not a hunt kind and is not issued.
 * After a LAN IP shares a line with a non-LAN unicast peer, eth-src, name-service,
 * Kerberos, and SAMR issue only for that C2-talking IP. Other LAN workstations,
 * the external peer, hostnames, and users do not receive those identity hunts.
 * @param added - identities appended on this tool result.
 * @param existing - hunts already on the session log.
 * @param evidenceText - current and prior tool-result text used to detect C2-talking LAN IPs.
 * @returns new hunts in issue order, unique against `existing` and themselves.
 */
export function huntsForNewIdentities(
  added: readonly Identity[],
  existing: readonly Hunt[],
  evidenceText = '',
): Hunt[] {
  const focusIps = new Set(c2TalkingLanIps(evidenceText))
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
    if (identity.kind === 'ip') {
      if (focusIps.size > 0 && !focusIps.has(identity.value)) continue
      issue('eth-src', identity)
      issue('name-service', identity)
      issue('kerberos-cname', identity)
      issue('samr-userinfo', identity)
      continue
    }
    if (focusIps.size > 0) continue
    if (identity.kind === 'hostname') {
      issue('kerberos-cname', identity)
      issue('samr-userinfo', identity)
    }
    if (identity.kind === 'user') issue('samr-userinfo', identity)
  }
  return out
}

/**
 * Display filter for one issued hunt. IP-subject hunts include `ip.addr == subject`.
 * @param filter - kind-specific display filter.
 * @param hunt - the hunt being noticed.
 * @returns the filter, scoped to the IP subject when present.
 */
function displayFilterFor(filter: string, hunt: Hunt): string {
  if (hunt.subjectKind !== 'ip') return filter
  return `(${filter}) and ip.addr == ${hunt.subject}`
}

/**
 * Model-facing notice for one issued hunt.
 * @param hunt - the hunt just appended.
 * @returns notice text naming the valid tshark 4.4.16 fields.
 */
export function huntNotice(hunt: Hunt): string {
  switch (hunt.kind) {
    case 'eth-src':
      return [
        `Hunt issued: eth-src for ${hunt.subjectKind} ${hunt.subject}.`,
        `Run pcap_filter with display_filter \`${displayFilterFor('eth.src', hunt)}\` and field \`eth.src\`.`,
      ].join(' ')
    case 'name-service':
      return [
        `Hunt issued: name-service for ${hunt.subjectKind} ${hunt.subject}.`,
        `Run pcap_filter with display_filter \`${displayFilterFor('llmnr or nbns or browser', hunt)}\`.`,
        'Those filters produce DESKTOP-* names, NBNS Registration, and BROWSER Host Announcement lines.',
      ].join(' ')
    case 'kerberos-cname':
      return [
        `Hunt issued: kerberos-cname for ${hunt.subjectKind} ${hunt.subject}.`,
        `Run pcap_filter with display_filter \`${displayFilterFor('kerberos.CNameString', hunt)}\` and field \`kerberos.CNameString\`.`,
        'Do not use kerberos.username, ldap.sAMAccountName, or ldap.displayName — those fields are invalid in tshark 4.4.16.',
        'Also run SAMR QueryUserInfo for this subject now with fields samr.samr_UserInfo21.account_name and samr.samr_UserInfo21.full_name (UTF-16 SAMR, not LDAP displayName). Do not wait for a username.',
      ].join(' ')
    case 'samr-userinfo':
      return [
        `Hunt issued: samr-userinfo for ${hunt.subjectKind} ${hunt.subject}.`,
        `Run pcap_filter with display_filter \`${displayFilterFor('samr.samr_UserInfo21.account_name or samr.samr_UserInfo21.full_name', hunt)}\``,
        'and fields `samr.samr_UserInfo21.account_name`, `samr.samr_UserInfo21.full_name`.',
        'SAMR full_name is UTF-16LE (Becka Rolf is the worked example), not ldap.displayName.',
      ].join(' ')
    default:
      return assertNever(hunt.kind, 'huntNotice')
  }
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
