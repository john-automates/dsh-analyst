/**
 * Groundedness: every indicator a close asserts must be one the investigation
 * actually observed.
 *
 * The failure this exists to stop is confabulation — a confidently stated
 * address or hostname that no packet carries. It is the failure that ends
 * analyst trust, because unlike a wrong verdict it cannot be argued with: the
 * thing simply is not there. Measured across thirteen graded investigations,
 * three of them asserted at least one such atom: two public IPv4s
 * (`66.234.159.108`, `173.166.146.112`) and one victim hostname
 * (`browser.host`) published on the who row.
 *
 * The standard here is `evidenceText` — the folded tool-result text — not the
 * capture file. That is deliberate and it is stricter: a claim must trace to
 * evidence this investigation gathered, not merely to something that happens to
 * be in a pcap nobody read. An agent that wants to assert an address must go
 * and look at it first.
 *
 * Structure follows the bind verifier's cascade, for the same reason: the exact
 * questions stay exact. Whether a string occurs in the evidence is arithmetic
 * and costs nothing. Only the leftover — "is this token even meant as an
 * indicator?" — needs a model, and that question is asked in {@link judge.ts}
 * about the flagged atoms alone, where it can release a false positive but
 * never manufacture a refusal.
 */
import { hostnamesEvidencedOnIp } from './harvest.ts'
import type { Identity } from './types.ts'

/** Deny prefix when the close asserts an indicator the evidence does not carry. */
export const UNGROUNDED_REASON =
  'unbound: the report asserts an indicator the evidence does not carry.'

const IPV4_TOKEN = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
/** A dotted name with a plausible TLD. Deliberately loose; the cascade narrows it. */
const NAME_TOKEN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi

/**
 * Windows and UNC paths, and CIDR prefixes, removed before tokens are read.
 *
 * `C:\Windows\Microsoft.NET\Framework` otherwise yields `microsoft.net` and
 * `185.14.92.0/24` yields its network base. Both are correct reporting, and
 * refusing a close over them would make the gate untrustworthy in the one
 * direction that matters — an analyst who learns the gate cries wolf stops
 * reading it.
 */
function stripNonIndicators(blob: string): string {
  return blob
    .replaceAll(/[A-Za-z]:\\[^\s"]*/g, ' ')
    .replaceAll(/\\{2}[^\s"]*/g, ' ')
    .replaceAll(/\b\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}\b/g, ' ')
}

/** The who/where slot keys that name a machine or account rather than prose. */
const IDENTITY_KEYS = ['hostname', 'user', 'full_name', 'mac', 'ip', 'entity_id'] as const

/** One identity value a close asserts, with the slot key that carried it. */
export interface AssertedIdentity {
  /** The who/where key. */
  key: (typeof IDENTITY_KEYS)[number]
  /** The lowercased value. */
  value: string
}

/**
 * Identity values a close submits on its who/where rows.
 *
 * Read by key rather than by shape, because shape is exactly what the
 * regex-only version got wrong in both directions: it flagged `keychain-2.db`
 * as a fabricated address, and it missed `browser.host` until a public suffix
 * happened to match. A NetBIOS name such as `DESKTOP-7XK2` has no dot at all
 * and would never have been read as an indicator, yet the who row is precisely
 * what names a real machine to a ticketing system.
 * @param args - submitted `case_report` arguments.
 * @returns identity values, lowercased, first-seen order.
 */
export function assertedIdentityValues(args: unknown): AssertedIdentity[] {
  const out: AssertedIdentity[] = []
  const seen = new Set<string>()
  const visit = (slot: unknown): void => {
    if (typeof slot !== 'object' || slot === null) return
    for (const key of IDENTITY_KEYS) {
      const value = (slot as Record<string, unknown>)[key]
      if (typeof value !== 'string') continue
      const norm = value.trim().toLowerCase()
      if (norm === '' || seen.has(`${key}:${norm}`)) continue
      seen.add(`${key}:${norm}`)
      out.push({ key, value: norm })
    }
  }
  const root = (typeof args === 'object' && args !== null ? args : {}) as Record<string, unknown>
  visit(root.who)
  visit(root.where)
  for (const row of Array.isArray(root.victims) ? root.victims : []) visit(row)
  return out
}

/**
 * Network indicators a close asserts: IPv4 addresses and DNS-shaped names.
 * @param args - submitted `case_report` arguments.
 * @returns lowercased atoms, first-seen order.
 */
export function assertedNetworkAtoms(args: unknown): string[] {
  const blob = stripNonIndicators(JSON.stringify(args ?? {}))
  const out: string[] = []
  const seen = new Set<string>()
  for (const match of [...blob.matchAll(IPV4_TOKEN), ...blob.matchAll(NAME_TOKEN)]) {
    const atom = match[0].toLowerCase().replace(/\.+$/, '')
    if (seen.has(atom)) continue
    seen.add(atom)
    out.push(atom)
  }
  return out
}

/**
 * Canonical form for comparing a hostname claim against harvested evidence.
 *
 * NetBIOS prints a suffix (`DESKTOP-7XK2<00>`) and pads to sixteen bytes,
 * Kerberos prints a machine account with a trailing `$`, and DHCP option 12 may
 * arrive in any case. Comparing raw would refuse correct hostnames — and the
 * cheapest way for an agent to satisfy a gate that refuses correct answers is
 * to stop asserting the field at all, trading a fabrication for an omission.
 * @param value - a hostname as claimed or as harvested.
 * @returns the comparable form.
 */
export function canonicalHostname(value: string): string {
  return value.trim().toLowerCase()
    .replace(/<[0-9a-f]{2}>\s*$/i, '')
    .replace(/\$$/, '')
    .replace(/\0/g, '')
    .trim()
}

/**
 * Whether `atom` occurs in the evidence, allowing the suffix relation a capture
 * and a report legitimately differ by.
 *
 * A post may name `example.com` while the capture resolved `www.example.com`,
 * or the reverse. Matching in one direction only would refuse one of those two
 * correct reports at random.
 * @param atom - the asserted atom, lowercased.
 * @param evidence - lowercased evidence text.
 * @param evidenceNames - lowercased names harvested from the evidence.
 * @returns true when the evidence supports the atom.
 */
function evidenced(atom: string, evidence: string, evidenceNames: readonly string[]): boolean {
  if (evidence.includes(atom)) return true
  return evidenceNames.some(name => name.endsWith(`.${atom}`) || atom.endsWith(`.${name}`))
}

/**
 * Atoms a close asserts that the evidence does not carry.
 *
 * Both classes are checked against the same evidence: network indicators by
 * occurrence with the suffix relation allowed, identity values by canonical
 * form. A close that asserts nothing checkable yields nothing, which is not a
 * pass so much as an absence of claims.
 * @param args - submitted `case_report` arguments.
 * @param evidenceText - tool-result text the investigation gathered.
 * @param identities - folded ledger identities.
 * @returns ungrounded atoms in first-seen order.
 */
export function ungroundedAtoms(
  args: unknown,
  evidenceText: string,
  identities: readonly Identity[] = [],
): string[] {
  const evidence = evidenceText.toLowerCase()
  const evidenceNames = identities
    .filter(item => item.kind === 'hostname')
    .map(item => canonicalHostname(item.value))
  const out: string[] = []
  for (const atom of assertedNetworkAtoms(args)) {
    if (!evidenced(atom, evidence, evidenceNames)) out.push(atom)
  }
  for (const { key, value } of assertedIdentityValues(args)) {
    const canonical = canonicalHostname(value)
    if (canonical === '' || out.includes(canonical)) continue
    // A hostname must come from something that NAMES HOSTS — a harvested NBNS,
    // DHCP option 12, Kerberos or SMB identity — never from "it appears
    // somewhere in the evidence".
    //
    // Occurrence is far too weak a standard for an identity, and the model
    // found that out before this check did: told to ground `browser.host`, a
    // run published `hostname: "tshark"` instead. That string is in every tool
    // result, so a substring test passes it, the gate never fires, and
    // groundedness reads 100% on a victim row naming the analysis tool. Swapping
    // a plausible fabrication for evidence-present nonsense is a worse report
    // and a better score, which is the definition of a gate that is measuring
    // the wrong thing.
    if (key === 'hostname') {
      if (!evidenceNames.includes(canonical)) out.push(canonical)
      continue
    }
    if (!evidenced(canonical, evidence, evidenceNames)) out.push(canonical)
  }
  return out
}

/**
 * Render the ungrounded-atom denial, naming each atom and, where one exists,
 * the evidenced value nearest to it.
 *
 * The deny text names what to do because the alternative correction — deleting
 * the claim — is always cheaper than getting it right, and a gate that is
 * easiest to satisfy by saying less makes a report worse.
 * @param atoms - ungrounded atoms.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text for evidenced hostnames.
 * @returns the deny reason.
 */
export function ungroundedDenyReason(
  atoms: readonly string[], identities: readonly Identity[], evidenceText: string,
): string {
  const listed = atoms.map((atom) => {
    const names = hostnamesEvidencedOnIp(atom, identities, evidenceText)
    return names.length === 0 ? atom : `${atom} (evidenced names: ${names.slice(0, 2).join(', ')})`
  })
  return `${UNGROUNDED_REASON} Unevidenced: ${listed.join('; ')}.`
    + ' Cite the frame or tool result that carries each one, or replace it with the'
    + ' value the evidence does carry. Do not delete the field to pass this check —'
    + ' an omitted victim hostname is worse than a corrected one.'
}
