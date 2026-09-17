import { describe, expect, it } from 'vitest'
import {
  assertedIdentityValues, assertedNetworkAtoms, canonicalHostname,
  UNGROUNDED_REASON, ungroundedAtoms, ungroundedDenyReason,
} from '../src/grounded.ts'
import { claimState, narrowToIndicatorClaims } from '../src/grounded-judge.ts'
import { harvestIdentities, identityOf } from '../src/harvest.ts'
import { denyCommand } from '../src/policy.ts'
import type { Identity } from '../src/types.ts'

const hostnames = (...values: string[]): Identity[] =>
  values.map(value => identityOf('hostname', value)).filter(item => item !== undefined)

describe('grounded: the fabrications measured on the corpus', () => {
  // Each of these three was published by a real graded investigation. They are
  // the reason the gate exists, so they are the first thing it must catch.
  it('refuses the two fabricated IPv4s from lumma-s2 and njrat-s2', () => {
    const evidence = 'DNS answer 64.89.161.173 futupath.cyou\nTCP 104.248.130.195:7492'
    expect(ungroundedAtoms({ what: 'contacted 66.234.159.108' }, evidence))
      .toEqual(['66.234.159.108'])
    expect(ungroundedAtoms({ why: 'beacon to 173.166.146.112 observed' }, evidence))
      .toEqual(['173.166.146.112'])
  })

  it('refuses the fabricated victim hostname from smartape1-s1', () => {
    const evidence = 'frame 12 ip.src == 10.5.27.101 eth.src == 00:08:02:1c:47:ae'
    const args = { who: { entity_id: '10.5.27.101', hostname: 'browser.host' } }
    expect(ungroundedAtoms(args, evidence)).toEqual(['browser.host'])
  })

  it('refuses a dotless NetBIOS-shaped hostname the old regex could never see', () => {
    // The gap this gate was built to close: no dot, so no name token, so the
    // previous check never looked at it at all.
    const args = { who: { entity_id: '10.5.27.101', hostname: 'DESKTOP-7XK2' } }
    expect(ungroundedAtoms(args, 'frame 12 ip.src == 10.5.27.101')).toEqual(['desktop-7xk2'])
    expect(assertedIdentityValues(args).map(i => i.value)).toContain('desktop-7xk2')
  })

  it('refuses a hostname that merely occurs in evidence, such as "tshark"', () => {
    // A live gated run answered the deny for `browser.host` by publishing
    // `hostname: "tshark"`. That string is in every tool result, so occurrence
    // passed it, the gate never fired, and groundedness read 100% on a victim
    // row naming the analysis tool. A hostname must come from something that
    // names hosts, not from anywhere in the text.
    const evidence = 'ip.src == 10.5.27.101 ... running tshark -r capture-1.pcap -Y dns'
    const args = { who: { entity_id: '10.5.27.101', hostname: 'tshark' } }
    expect(ungroundedAtoms(args, evidence, harvestIdentities(evidence))).toEqual(['tshark'])
  })

  it('still accepts a hostname harvested from a host-naming source', () => {
    const ids = hostnames('desktop-7xk2')
    const args = { who: { hostname: 'DESKTOP-7XK2' } }
    expect(ungroundedAtoms(args, 'nbns chatter', ids)).toEqual([])
  })
})

describe('grounded: what it must not refuse', () => {
  it('accepts a NetBIOS name that the evidence pads and suffixes', () => {
    // Harvested the way the call site harvests, so the padding and the `<00>`
    // suffix are exercised through the real identity path.
    const evidence = 'NBNS name DESKTOP-7XK2<00> registration from 10.5.27.101'
    const args = { who: { entity_id: '10.5.27.101', hostname: 'DESKTOP-7XK2' } }
    const ids = [...harvestIdentities(evidence), ...hostnames('desktop-7xk2')]
    expect(ungroundedAtoms(args, evidence, ids)).toEqual([])
  })

  it('accepts a Kerberos machine account written with its trailing dollar', () => {
    expect(canonicalHostname('DESKTOP-7XK2$')).toBe('desktop-7xk2')
    expect(canonicalHostname('DESKTOP-7XK2<20> ')).toBe('desktop-7xk2')
    const ids = hostnames('desktop-7xk2$')
    expect(ungroundedAtoms({ who: { hostname: 'DESKTOP-7XK2' } }, 'kerberos', ids)).toEqual([])
  })

  it('accepts a bare name against a www-prefixed capture, and the reverse', () => {
    const ids = hostnames('www.example.com')
    expect(ungroundedAtoms({ what: 'contacted example.com' }, 'sni www.example.com', ids))
      .toEqual([])
    const bare = hostnames('example.com')
    expect(ungroundedAtoms({ what: 'contacted www.example.com' }, 'dns example.com', bare))
      .toEqual([])
  })

  it('does not read a Windows path, a CIDR, or a bundle id as an indicator', () => {
    // Each of these produced a false positive in the bench's first version:
    // microsoft.net from a path, the network base from a CIDR.
    const args = {
      how: 'C:\\Windows\\Microsoft.NET\\Framework and \\\\server\\share',
      why: 'range 185.14.92.0/24 was scanned',
    }
    expect(ungroundedAtoms(args, 'no indicators here')).toEqual([])
  })

  it('reads identity slots by key, including victims rows', () => {
    const args = {
      who: { entity_id: '10.1.1.1', hostname: 'HOST-A', user: 'first.last' },
      where: { hostname: 'HOST-B' },
      victims: [{ hostname: 'HOST-C' }],
    }
    const values = assertedIdentityValues(args).map(item => item.value)
    expect(values).toContain('host-a')
    expect(values).toContain('host-b')
    expect(values).toContain('host-c')
    // `first.last` is a real account shape the ledger's own regex rejects; the
    // gate must still surface it rather than silently skip it.
    expect(values).toContain('first.last')
  })

  it('names each atom and what to do, and says not to delete the field', () => {
    const reason = ungroundedDenyReason(['browser.host'], [], '')
    expect(reason.startsWith(UNGROUNDED_REASON)).toBe(true)
    expect(reason).toContain('browser.host')
    expect(reason).toContain('Do not delete the field')
  })

  it('collects network atoms once, in first-seen order', () => {
    const atoms = assertedNetworkAtoms({ a: '1.2.3.4 evil.com', b: '1.2.3.4' })
    expect(atoms).toEqual(['1.2.3.4', 'evil.com'])
  })
})

describe('grounded-judge: judgment may release, never refuse', () => {
  const ctxWith = (noul: () => Promise<{ noul: number }>): never =>
    ({ get: (name: string) => (name === 'judgment' ? { noul } : undefined) } as never)

  it('returns the deny list unchanged when no provider is mounted', async () => {
    const ctx = { get: () => undefined } as never
    expect(await narrowToIndicatorClaims(ctx, ['a.com', 'b.com'], {}))
      .toEqual(['a.com', 'b.com'])
  })

  it('releases an atom the model says is not an indicator claim', async () => {
    const ctx = ctxWith(async () => ({ noul: 0.05 }))
    expect(await narrowToIndicatorClaims(ctx, ['keychain-2.db'], {})).toEqual([])
  })

  it('keeps an atom the model confirms is an indicator claim', async () => {
    const ctx = ctxWith(async () => ({ noul: 0.93 }))
    expect(await narrowToIndicatorClaims(ctx, ['66.234.159.108'], {}))
      .toEqual(['66.234.159.108'])
  })

  it('keeps the atom when the backend fails, so an outage cannot release one', async () => {
    const ctx = ctxWith(async () => { throw new Error('backend down') })
    expect(await narrowToIndicatorClaims(ctx, ['66.234.159.108'], {}))
      .toEqual(['66.234.159.108'])
  })

  it('asks about the window around the token, not the whole report', () => {
    const state = claimState('evil.com', { what: `${'x'.repeat(500)} evil.com tail` }) as {
      token: string
      how_the_report_uses_it: string
    }
    expect(state.token).toBe('evil.com')
    expect(state.how_the_report_uses_it).toContain('evil.com')
    expect(state.how_the_report_uses_it.length).toBeLessThan(500)
  })
})

describe('policy: network reachback', () => {
  const CASE = '/case'
  const deny = (command: string, on = true): string | undefined =>
    denyCommand(command, CASE, true, on)

  it('refuses the exact reachback a graded run performed', () => {
    // `cd <case> && (timeout 6 getent hosts <ip>)` — head token is `cd`, so a
    // head-only check passes it. This is the command that put four rDNS names
    // into a report the capture never carried.
    const real = 'cd /case && (timeout 6 getent hosts 5.252.177.69 > analysis/net1.txt)'
    expect(deny(real)).toContain('getent')
    expect(deny(real)).toContain('forbids reachback')
  })

  it('refuses curl, dig, and openssl s_client anywhere in the command', () => {
    expect(deny('curl -s https://dns.google/resolve?name=x.com')).toContain('curl')
    expect(deny('cd /case && dig -x 1.2.3.4')).toContain('dig')
    expect(deny('openssl s_client -connect a.b:443')).toContain('openssl s_client')
  })

  it('allows local openssl and ordinary capture work', () => {
    expect(deny('openssl x509 -in /case/analysis/cert.der -inform DER -text')).toBeUndefined()
    expect(deny('tshark -r /case/capture-1.pcap -Y "dns"')).toBeUndefined()
    expect(deny('grep -i host /case/analysis/http.txt')).toBeUndefined()
  })

  it('is off by default, so a customer investigation keeps its tradecraft', () => {
    expect(deny('dig -x 1.2.3.4', false)).toBeUndefined()
    expect(denyCommand('curl https://example.com', CASE, true)).toBeUndefined()
  })
})
