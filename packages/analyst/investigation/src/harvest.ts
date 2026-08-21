/**
 * Extract unique labeled identities from tool-result text, including hostnames
 * taken from NBNS, BROWSER, SMB, and LLMNR tshark summaries. After a
 * C2-talking LAN IP is known, MAC harvest records only eth.src sourced from
 * that IP.
 * @module @deepseek-ai/dsh-investigation/harvest
 */

import { c2TalkingLanIps } from './hunts.ts'
import type { Identity, IdentityKind } from './types.ts'

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
const MAC = /(?<![0-9a-fA-F]:)(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![:-][0-9a-fA-F]{2})/g
const SKIP_IPS = new Set(['0.0.0.0', '255.255.255.255'])
const DOTTED_IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/
const IP_SRC_LABEL = /(?:^|[\s,;|])ip\.src\s*[:=]\s*(\d{1,3}(?:\.\d{1,3}){3})/i
const ETH_SRC_LABEL = /(?:^|[\s,;|])eth\.src\s*[:=]\s*((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})/i
const IP_CONVERSATION = /(\d{1,3}(?:\.\d{1,3}){3})\s*(?:→|->)\s*(\d{1,3}(?:\.\d{1,3}){3})/
const ARP_IS_AT = /(\d{1,3}(?:\.\d{1,3}){3})\s+is at\s+((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})/i

const HOST_LABEL = /(?:^|[\s,;|])(?:hostname|host|nbns\.name|dns\.qry\.name)\s*[:=]\s*(\w[\w.-]{0,253})/gi
const USER_LABEL = /(?:^|[\s,;|])(?:user|username|account_name|kerberos\.CNameString|CNameString|cname)\s*[:=]\s*([^\s,;|]*)/gi
const NAME_LABEL = /(?:^|[\s,;|])(?:full_name|full name|samr\.samr_UserInfo21\.full_name)\s*[:=]\s*(.+)$/gim

// tshark default Info text names hosts without hostname:= labels.
// Domain/Workgroup and Local Master announcements, and NBNS <1b>–<1e>, are workgroup/domain tokens.
const LLMNR_QUERY_TYPES = 'A|AAAA|ANY|PTR|CNAME|NS|MX|TXT|SRV|SOA'
const LLMNR_SUMMARY_HOST = new RegExp(
  String.raw`\bLLMNR\b[^\n]*?\b(?:Standard query|query)(?:\s+response)?` +
    String.raw`(?:\s+0x[0-9a-f]+)?\s+(?:${LLMNR_QUERY_TYPES})\s+([a-z][\w.-]{0,253})`,
  'gi',
)
const NBNS_HOST_SUFFIX = /\bNBNS\b[^\n]*?\bNB\s+([a-z][\w.-]{0,14})<(?:00|03|20)>/gi
const NBNS_WORKGROUP_SUFFIX = /\bNBNS\b[^\n]*?\bNB\s+([a-z][\w.-]{0,14})<(?:1[b-e])>/gi
const BROWSER_HOST_ANNOUNCE = /\bBROWSER\b[^\n]*?\bHost Announcement\s+([a-z][\w.-]{0,14})/gi
const BROWSER_REQUEST_ANNOUNCE = /\bBROWSER\b[^\n]*?\bRequest Announcement\s+([a-z][\w.-]{0,14})/gi
const BROWSER_WORKGROUP_ANNOUNCE =
  /\bBROWSER\b[^\n]*?\b(?:Domain\/Workgroup Announcement|Local Master Announcement)\s+([a-z][\w.-]{0,14})/gi
const SMB_UNC_HOST = /\bSMB2?\b[^\n]*?\\\\([a-z][\w.-]{0,253})\\/gi
const SUMMARY_HOST_PATTERNS = [
  LLMNR_SUMMARY_HOST,
  NBNS_HOST_SUFFIX,
  BROWSER_HOST_ANNOUNCE,
  BROWSER_REQUEST_ANNOUNCE,
  SMB_UNC_HOST,
] as const

/** Display labels for each identity kind. */
export const IDENTITY_LABELS: Readonly<Record<IdentityKind, string>> = {
  ip: 'IP',
  mac: 'MAC',
  hostname: 'hostname',
  user: 'user',
  full_name: 'full name',
}

/**
 * Normalize one identity value for uniqueness.
 * @param kind - identity kind.
 * @param value - raw harvested value.
 * @returns trimmed, kind-specific canonical value, or undefined when empty.
 */
export function normalizeIdentityValue(kind: IdentityKind, value: string): string | undefined {
  const trimmed = value.trim()
  if (trimmed === '') return undefined
  if (kind === 'mac') return trimmed.toLowerCase().replace(/-/g, ':')
  if (kind === 'hostname' || kind === 'ip') return trimmed.toLowerCase()
  if (kind === 'full_name') return trimmed.replace(/\s+/g, ' ')
  return trimmed
}

/**
 * Decode a SAMR UTF-16LE hex dump (colon-separated or contiguous) to text.
 * @param raw - hex bytes, optionally colon- or space-separated.
 * @returns printable decoded text, or undefined when the bytes are not UTF-16LE text.
 */
export function decodeUtf16LeHex(raw: string): string | undefined {
  const hex = raw.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '')
  if (hex.length < 8 || hex.length % 4 !== 0) return undefined
  const text = Buffer.from(hex, 'hex').toString('utf16le').replace(/\u0000+$/g, '')
  if (text.length < 2 || !/^[\p{L}\p{N} .,'-]+$/u.test(text)) return undefined
  return text
}

/**
 * Build one identity record after normalization.
 * @param kind - identity kind.
 * @param value - raw value.
 * @returns the identity, or undefined when the value is empty after normalize.
 */
export function identityOf(kind: IdentityKind, value: string): Identity | undefined {
  const normalized = normalizeIdentityValue(kind, value)
  if (normalized === undefined) return undefined
  return { kind, value: normalized, label: IDENTITY_LABELS[kind] }
}

/**
 * Harvest unique labeled identities from tool-result text.
 * Hostname also comes from NBNS, BROWSER, SMB, and LLMNR tshark summaries.
 * Workgroup and domain tokens distinguished as Domain/Workgroup Announcement,
 * Local Master Announcement, or NBNS `<1b>`–`<1e>` are not recorded as hostname.
 * After `c2TalkingLanIps` finds a focus IP, a MAC is recorded only when it is
 * sourced from that IP (`ip.src`, outbound `focus → peer`, or ARP `is at`).
 * A bidirectional dump cannot persist the far-side NIC.
 * @param text - rendered tool output being harvested.
 * @param evidenceText - current and prior tool-result text used to detect C2-talking LAN IPs.
 * @returns identities in first-seen order, unique on kind+value.
 */
export function harvestIdentities(text: string, evidenceText = text): Identity[] {
  const seen = new Set<string>()
  const out: Identity[] = []
  const add = (kind: IdentityKind, value: string): void => {
    const identity = identityOf(kind, value)
    if (identity === undefined) return
    const key = `${identity.kind}\0${identity.value}`
    if (seen.has(key)) return
    seen.add(key)
    out.push(identity)
  }

  for (const match of text.matchAll(IPV4)) {
    const ip = match[0]
    if (!SKIP_IPS.has(ip)) add('ip', ip)
  }
  harvestMacs(text, new Set(c2TalkingLanIps(evidenceText)), add)

  for (const match of text.matchAll(HOST_LABEL)) {
    const host = regexCapture(match)
    if (host !== '' && !DOTTED_IPV4.test(host)) add('hostname', host)
  }

  const workgroups = new Set<string>()
  for (const match of text.matchAll(NBNS_WORKGROUP_SUFFIX)) {
    workgroups.add(regexCapture(match).toLowerCase())
  }
  for (const match of text.matchAll(BROWSER_WORKGROUP_ANNOUNCE)) {
    workgroups.add(regexCapture(match).toLowerCase())
  }
  for (const pattern of SUMMARY_HOST_PATTERNS) {
    for (const match of text.matchAll(pattern)) {
      const host = regexCapture(match)
      if (workgroups.has(host.toLowerCase())) continue
      add('hostname', host)
    }
  }

  for (const match of text.matchAll(USER_LABEL)) {
    add('user', regexCapture(match))
  }
  for (const match of text.matchAll(NAME_LABEL)) {
    const raw = regexCapture(match)
    add('full_name', decodeUtf16LeHex(raw) ?? raw)
  }

  for (const match of text.matchAll(/\b((?:[0-9a-fA-F]{2}:){7,}[0-9a-fA-F]{2})\b/g)) {
    const decoded = decodeUtf16LeHex(regexCapture(match))
    if (decoded !== undefined) add('full_name', decoded)
  }
  return out
}

/**
 * Identity uniqueness key.
 * @param identity - one identity.
 * @returns kind+value key.
 */
export function identityKey(identity: Identity): string {
  return `${identity.kind}\0${identity.value}`
}

/**
 * Record MACs. With no C2-talking focus, every MAC is kept. With a focus IP,
 * only a MAC sourced from that IP is kept; a bidirectional dump cannot persist
 * the far-side NIC.
 */
function harvestMacs(
  text: string,
  focusIps: ReadonlySet<string>,
  add: (kind: IdentityKind, value: string) => void,
): void {
  if (focusIps.size === 0) {
    for (const match of text.matchAll(MAC)) add('mac', match[0])
    return
  }
  let sourced = false
  for (const line of text.split(/\r?\n/)) {
    const mac = macSourcedFromFocusIp(line, focusIps)
    if (mac === undefined) continue
    sourced = true
    add('mac', mac)
  }
  if (sourced || hasIpv4(text)) return
  const majority = majorityLabeledEthSrc(text)
  if (majority !== undefined) add('mac', majority)
}

/**
 * MAC on one line that is sourced from a C2-talking LAN IP.
 * Labeled `ip.src`, outbound `focus → peer`, or ARP `is at` qualify.
 * Inbound `peer → focus` and idle-workstation lines do not.
 * @param line - one tool-output line.
 * @param focusIps - C2-talking LAN IPs.
 * @returns the sourced MAC, or undefined when this line has none.
 */
function macSourcedFromFocusIp(line: string, focusIps: ReadonlySet<string>): string | undefined {
  const ipSrc = labeledIpv4(line, IP_SRC_LABEL)
  const ethSrc = labeledField(line, ETH_SRC_LABEL)
  if (ipSrc !== undefined) {
    if (!focusIps.has(ipSrc)) return undefined
    return ethSrc ?? firstMac(line)
  }
  const arp = ARP_IS_AT.exec(line)
  const arpIp = arp?.[1]
  const arpMac = arp?.[2]
  if (arpIp !== undefined && arpMac !== undefined && focusIps.has(arpIp)) return arpMac
  const conversation = IP_CONVERSATION.exec(line)
  const srcIp = conversation?.[1]
  if (srcIp !== undefined && focusIps.has(srcIp)) return ethSrc ?? firstMac(line)
  return undefined
}

/**
 * Strict-majority labeled `eth.src` when a field-only dump has no IPv4.
 * A tie records nothing so a bidirectional dump cannot win.
 * @param text - tool output with `eth.src` columns and no IPv4.
 * @returns the majority MAC, or undefined on a tie or empty dump.
 */
function majorityLabeledEthSrc(text: string): string | undefined {
  const counts = new Map<string, number>()
  for (const match of text.matchAll(new RegExp(ETH_SRC_LABEL, 'gi'))) {
    const mac = regexCapture(match).toLowerCase().replace(/-/g, ':')
    counts.set(mac, (counts.get(mac) ?? 0) + 1)
  }
  let best: string | undefined
  let bestCount = 0
  let tied = false
  for (const [mac, count] of counts) {
    if (count > bestCount) {
      best = mac
      bestCount = count
      tied = false
    } else if (count === bestCount) {
      tied = true
    }
  }
  return tied ? undefined : best
}

function hasIpv4(text: string): boolean {
  return new RegExp(IPV4.source).test(text)
}

function labeledIpv4(line: string, pattern: RegExp): string | undefined {
  const value = labeledField(line, pattern)
  if (value === undefined) return undefined
  return new RegExp(`^${IPV4.source}$`).test(value) ? value : undefined
}

function labeledField(line: string, pattern: RegExp): string | undefined {
  const match = pattern.exec(line)
  if (match === null) return undefined
  return regexCapture(match)
}

function firstMac(line: string): string | undefined {
  return new RegExp(MAC.source).exec(line)?.[0]
}

/**
 * Read a regex capture group, treating a missing group as empty.
 * @param match - a successful match.
 * @param index - capture index, default 1.
 * @returns the captured string, or an empty string.
 */
export function regexCapture(match: RegExpMatchArray, index = 1): string {
  return match[index] ?? ''
}
