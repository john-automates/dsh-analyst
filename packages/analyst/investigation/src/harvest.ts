/**
 * Extract unique labeled identities from tool-result text.
 * @module @deepseek-ai/dsh-investigation/harvest
 */

import type { Identity, IdentityKind } from './types.ts'

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
const MAC = /\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b/g
const SKIP_IPS = new Set(['0.0.0.0', '255.255.255.255'])

const HOST_LABEL = /(?:^|[\s,;|])(?:hostname|host|nbns\.name|dns\.qry\.name)\s*[:=]\s*(\w[\w.-]{0,253})/gi
const USER_LABEL = /(?:^|[\s,;|])(?:user|username|account_name|kerberos\.CNameString|CNameString|cname)\s*[:=]\s*([^\s,;|]+)/gi
const NAME_LABEL = /(?:^|[\s,;|])(?:full_name|full name|samr\.samr_UserInfo21\.full_name)\s*[:=]\s*(.+)$/gim

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
 * @param text - rendered tool output.
 * @returns identities in first-seen order, unique on kind+value.
 */
export function harvestIdentities(text: string): Identity[] {
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
  for (const match of text.matchAll(MAC)) add('mac', match[0])

  for (const match of text.matchAll(HOST_LABEL)) {
    const host = match[1]
    if (host !== undefined && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) add('hostname', host)
  }
  for (const match of text.matchAll(USER_LABEL)) {
    const user = match[1]
    if (user !== undefined) add('user', user)
  }
  for (const match of text.matchAll(NAME_LABEL)) {
    const raw = match[1]
    if (raw === undefined) continue
    add('full_name', decodeUtf16LeHex(raw) ?? raw)
  }

  for (const match of text.matchAll(/\b((?:[0-9a-fA-F]{2}:){7,}[0-9a-fA-F]{2})\b/g)) {
    const decoded = decodeUtf16LeHex(match[1] ?? '')
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
