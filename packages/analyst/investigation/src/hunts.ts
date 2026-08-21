/**
 * Auto-issued hunt selection after newly recorded identities, the
 * other-end hunt issued when bind_relationship assigns a cue as victim,
 * the extra-wan hunt issued on a successful bind for other WAN peers of
 * the bound victim, and the c2-domain hunt issued for each C2 IPv4.
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
 * Display filter that finds LAN `ip.src` talking to a cue/observation address.
 * @param cue - normalized cue/observation IPv4.
 * @returns `ip.dst == <cue>`.
 */
export function otherEndDisplayFilter(cue: string): string {
  return `ip.dst == ${cue}`
}

/**
 * Hunt for LAN sources talking to a cue/observation address.
 * Subject is the cue IP. The filter does not invent a LAN peer.
 * @param cue - normalized cue/observation IPv4.
 * @returns an `other-end` hunt for that cue.
 */
export function otherEndHunt(cue: string): Hunt {
  return { kind: 'other-end', subjectKind: 'ip', subject: cue }
}

/**
 * Display filter that finds TLS SNI or DNS names on a bound C2 IPv4.
 * @param c2 - normalized non-LAN C2 IPv4.
 * @returns SNI/DNS filter scoped with `ip.addr == <c2>`.
 */
export function c2DomainDisplayFilter(c2: string): string {
  return displayFilterFor(
    'tls.handshake.extensions_server_name or dns.qry.name or dns.resp.name',
    c2DomainHunt(c2),
  )
}

/**
 * Hunt for a TLS SNI or DNS name evidenced on a bound C2 IPv4.
 * Subject is that C2 IP. The filter does not invent a domain.
 * @param c2 - normalized non-LAN C2 IPv4.
 * @returns a `c2-domain` hunt for that C2.
 */
export function c2DomainHunt(c2: string): Hunt {
  return { kind: 'c2-domain', subjectKind: 'ip', subject: c2 }
}

/**
 * Display-filter clauses that keep `ip.dst` off LAN, loopback, link-local,
 * multicast, reserved, and 0.0.0.0. Gateway and DC addresses in RFC1918
 * stay out. Broadcast 255.255.255.255 is in 224.0.0.0/3.
 */
const NON_LAN_UNICAST_DST = [
  'not (ip.dst == 10.0.0.0/8 or ip.dst == 172.16.0.0/12 or ip.dst == 192.168.0.0/16)',
  'not (ip.dst == 127.0.0.0/8 or ip.dst == 169.254.0.0/16 or ip.dst == 224.0.0.0/3)',
  'not ip.dst == 0.0.0.0',
].join(' and ')

/**
 * Display filter that finds `ip.src ==` the bound victim talking to a
 * non-LAN unicast destination that is not the already-bound C2.
 * @param victim - normalized LAN victim IPv4.
 * @param boundC2 - bound non-LAN C2 IPv4, when known.
 * @returns `ip.src` plus non-LAN dest exclusions, and `not ip.dst ==` the C2.
 */
export function extraWanDisplayFilter(victim: string, boundC2?: string): string {
  const parts = [`ip.src == ${victim}`, NON_LAN_UNICAST_DST]
  if (boundC2 !== undefined) parts.push(`not ip.dst == ${boundC2}`)
  return parts.join(' and ')
}

/**
 * Hunt for other WAN destinations of a bound victim IPv4.
 * Subject is that victim IP. The filter does not invent a peer.
 * @param victim - normalized LAN victim IPv4.
 * @returns an `extra-wan` hunt for that victim.
 */
export function extraWanHunt(victim: string): Hunt {
  return { kind: 'extra-wan', subjectKind: 'ip', subject: victim }
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
 * Display filter for one issued hunt. IP-subject hunts include `ip.addr == subject`,
 * except `eth-src`, which uses `ip.src ==` so a bidirectional dump cannot win.
 * @param filter - kind-specific display filter.
 * @param hunt - the hunt being noticed or executed.
 * @returns the filter, scoped to the IP subject when present.
 */
export function displayFilterFor(filter: string, hunt: Hunt): string {
  if (hunt.subjectKind !== 'ip') return filter
  const ipField = hunt.kind === 'eth-src' ? 'ip.src' : 'ip.addr'
  return `(${filter}) and ${ipField} == ${hunt.subject}`
}

/** Scoped `pcap_filter` arguments for one issued hunt. */
export interface HuntFilterSpec {
  /** Display filter, including `ip.src` / `ip.addr` when the subject is an IP. */
  display_filter: string
  /** tshark `-e` names. Empty when the hunt reads default Info text. */
  fields: readonly string[]
}

/**
 * Scoped display_filter and fields for one issued hunt.
 * Matches the filters named in {@link huntNotice}.
 * @param hunt - the hunt to execute or notice.
 * @param boundC2 - bound non-LAN C2 IPv4, used to exclude that dest
 * from `extra-wan`.
 * extra-wan `ip.dst` dumps unique-collapse in first-seen order before the
 * `pcap_filter` output clip.
 * @returns filter and fields for `pcap_filter`.
 */
export function huntFilterSpec(hunt: Hunt, boundC2?: string): HuntFilterSpec {
  switch (hunt.kind) {
    case 'eth-src':
      return { display_filter: displayFilterFor('eth.src', hunt), fields: ['eth.src'] }
    case 'name-service':
      return { display_filter: displayFilterFor('llmnr or nbns or browser', hunt), fields: [] }
    case 'kerberos-cname':
      return { display_filter: displayFilterFor('kerberos.CNameString', hunt), fields: ['kerberos.CNameString'] }
    case 'samr-userinfo':
      return {
        display_filter: displayFilterFor(
          'samr.samr_UserInfo21.account_name or samr.samr_UserInfo21.full_name',
          hunt,
        ),
        fields: ['samr.samr_UserInfo21.account_name', 'samr.samr_UserInfo21.full_name'],
      }
    case 'other-end':
      return { display_filter: otherEndDisplayFilter(hunt.subject), fields: ['ip.src'] }
    case 'c2-domain':
      return {
        display_filter: c2DomainDisplayFilter(hunt.subject),
        fields: [
          'tls.handshake.extensions_server_name',
          'dns.qry.name',
          'dns.resp.name',
        ],
      }
    case 'extra-wan':
      return {
        display_filter: extraWanDisplayFilter(hunt.subject, boundC2),
        fields: ['ip.dst'],
      }
    default:
      return assertNever(hunt.kind, 'huntFilterSpec')
  }
}

/**
 * Whether an issued hunt may be auto-run against a capture.
 * Non-LAN / C2 IP subjects never run, except `other-end` (LAN `ip.src`
 * talking to that cue) and `c2-domain` (TLS SNI / DNS on that C2).
 * `extra-wan` runs for a LAN victim subject even when a C2-talking focus
 * IP exists. When a C2-talking LAN IP is known, only hunts for that IP
 * run (and those exceptions). Otherwise LAN IP, hostname, and user
 * subjects run.
 * @param hunt - one issued hunt.
 * @param evidenceText - current and prior tool-result text used to detect C2-talking LAN IPs.
 * @returns true when the plugin should execute this hunt.
 */
export function shouldAutoRunHunt(hunt: Hunt, evidenceText: string): boolean {
  if (hunt.kind === 'other-end' || hunt.kind === 'c2-domain') {
    return hunt.subjectKind === 'ip' && isNonLanUnicastIpv4(hunt.subject)
  }
  if (hunt.kind === 'extra-wan') {
    return hunt.subjectKind === 'ip' && isLanIpv4(hunt.subject)
  }
  if (hunt.subjectKind === 'ip' && isNonLanUnicastIpv4(hunt.subject)) return false
  const focus = c2TalkingLanIps(evidenceText)
  if (focus.length > 0) return hunt.subjectKind === 'ip' && focus.includes(hunt.subject)
  if (hunt.subjectKind === 'ip') return isLanIpv4(hunt.subject)
  return true
}

/**
 * Issued hunts that have not been executed and are eligible to auto-run.
 * When a C2-talking LAN IP is known, only that subject's hunts are returned.
 * @param hunts - hunts already on the session log.
 * @param evidenceText - current and prior tool-result text used to detect C2-talking LAN IPs.
 * @param executed - hunt keys already auto-run (or attempted) on this service.
 * @param ready - Plan-ready. When false, every hunt stays off, including
 *   identity hunts and `other-end`. Default false so Mission alone cannot
 *   unlock auto-hunts.
 * @returns eligible hunts in issue order.
 */
export function huntsToAutoRun(
  hunts: readonly Hunt[],
  evidenceText: string,
  executed: ReadonlySet<string>,
  ready = false,
): Hunt[] {
  if (!ready) return []
  return hunts.filter((hunt) => {
    if (executed.has(huntKey(hunt))) return false
    return shouldAutoRunHunt(hunt, evidenceText)
  })
}

/**
 * Model-facing notice for one issued hunt.
 * @param hunt - the hunt just appended.
 * @returns notice text naming the valid tshark 4.4.16 fields.
 */
export function huntNotice(hunt: Hunt): string {
  switch (hunt.kind) {
    case 'eth-src': {
      const spec = huntFilterSpec(hunt)
      return [
        `Hunt issued: eth-src for ${hunt.subjectKind} ${hunt.subject}.`,
        `Filter \`${spec.display_filter}\` field \`${spec.fields[0]}\`.`,
      ].join(' ')
    }
    case 'name-service': {
      const spec = huntFilterSpec(hunt)
      return [
        `Hunt issued: name-service for ${hunt.subjectKind} ${hunt.subject}.`,
        `Filter \`${spec.display_filter}\`.`,
        'Those filters produce DESKTOP-* names, NBNS Registration, and BROWSER Host Announcement lines.',
      ].join(' ')
    }
    case 'kerberos-cname': {
      const spec = huntFilterSpec(hunt)
      return [
        `Hunt issued: kerberos-cname for ${hunt.subjectKind} ${hunt.subject}.`,
        `Filter \`${spec.display_filter}\` field \`${spec.fields[0]}\`.`,
        'Do not use kerberos.username, ldap.sAMAccountName, or ldap.displayName — those fields are invalid in tshark 4.4.16.',
        'Also run SAMR QueryUserInfo for this subject now with fields samr.samr_UserInfo21.account_name and samr.samr_UserInfo21.full_name (UTF-16 SAMR, not LDAP displayName). Do not wait for a username.',
      ].join(' ')
    }
    case 'samr-userinfo': {
      const spec = huntFilterSpec(hunt)
      return [
        `Hunt issued: samr-userinfo for ${hunt.subjectKind} ${hunt.subject}.`,
        `Filter \`${spec.display_filter}\``,
        `fields \`${spec.fields[0]}\`, \`${spec.fields[1]}\`.`,
        'SAMR full_name is UTF-16LE (Becka Rolf is the worked example), not ldap.displayName.',
      ].join(' ')
    }
    case 'other-end': {
      const spec = huntFilterSpec(hunt)
      return [
        `Hunt issued: other-end for ${hunt.subjectKind} ${hunt.subject}.`,
        `Filter \`${spec.display_filter}\` field \`${spec.fields[0]}\`.`,
      ].join(' ')
    }
    case 'c2-domain': {
      const spec = huntFilterSpec(hunt)
      return [
        `Hunt issued: c2-domain for ${hunt.subjectKind} ${hunt.subject}.`,
        `Filter \`${spec.display_filter}\``,
        `fields \`${spec.fields[0]}\`, \`${spec.fields[1]}\`, \`${spec.fields[2]}\`.`,
      ].join(' ')
    }
    case 'extra-wan': {
      const spec = huntFilterSpec(hunt)
      return [
        `Hunt issued: extra-wan for ${hunt.subjectKind} ${hunt.subject}.`,
        `Filter \`${spec.display_filter}\` field \`${spec.fields[0]}\`.`,
      ].join(' ')
    }
    default:
      return assertNever(hunt.kind, 'huntNotice')
  }
}
