import { Context } from '@deepseek-ai/cordis'
import JudgmentRuntime, { type JudgmentProvider } from '@deepseek-ai/dsh-judgment/src/index.ts'
import { describe, expect, it } from 'vitest'
import {
  C2_IS_BENIGN_SERVICE,
  DEFAULT_DROP_GATE,
  DEFAULT_VERIFY_GATE,
  droppableDestinations,
  judgeCdnOrUpdate,
  verifyState,
} from '@deepseek-ai/dsh-investigation/src/verify.ts'
import {
  C2_ROLE_RULE,
  C2_ROLE_RULE_VERIFIED,
  bindRelationshipDescription,
  candidateC2Addrs,
  keepPublishedSlotFields,
  undisposedDenyReason,
  undisposedDestinations,
  wanPeersOfVictim,
  methodologySection,
  projectVictimSlot,
  resolveBind,
  normalizeIdentityValue,
} from '@deepseek-ai/dsh-investigation'
import type { Identity } from '@deepseek-ai/dsh-investigation'

/** `kernel-87.com` on a published Cloudflare address, as the AMOS capture shows it. */
const CLOUDFLARE_C2 = '104.21.74.178'
const VICTIM = '10.9.8.128'

const hostname = (value: string, ip: string): Identity =>
  ({ kind: 'hostname', value, label: 'hostname', evidence_id: ip })

/** A context carrying a judgment seam whose single provider answers `noul`. */
async function ctxWithJudgment(noul: number | Error): Promise<Context> {
  const ctx = new Context()
  await ctx.plugin(JudgmentRuntime, {})
  const provider: JudgmentProvider = {
    id: 'scripted',
    available: () => true,
    ask: () => noul instanceof Error
      ? Promise.reject(noul)
      : Promise.resolve({ answers: { q: { type: 'noul' as const, noul } }, model: 'test' }),
  }
  ctx.judgment.register(provider)
  return ctx
}

describe('verifyState', () => {
  it('carries the evidenced names and the prefix tests as evidence', () => {
    const state = verifyState(CLOUDFLARE_C2, [hostname('kernel-87.com', CLOUDFLARE_C2)], '') as {
      endpoint_labelled_c2: Record<string, unknown>
    }
    expect(state.endpoint_labelled_c2).toMatchObject({
      address: CLOUDFLARE_C2,
      in_a_published_cloudflare_anycast_prefix: true,
      in_a_published_fastly_anycast_prefix: false,
      a_name_matches_a_known_cdn_or_update_domain: false,
    })
    expect(state.endpoint_labelled_c2.names_evidenced_in_the_capture)
      .toContain('kernel-87.com')
  })

  it('states the question as a fault to detect', () => {
    expect(C2_IS_BENIGN_SERVICE).toContain('Something is wrong with this bind')
  })
})

describe('judgeCdnOrUpdate', () => {
  it('returns undefined when no judgment provider is mounted', async () => {
    await expect(judgeCdnOrUpdate(new Context(), CLOUDFLARE_C2, [], '')).resolves.toBeUndefined()
  })

  it('refuses at or above the gate', async () => {
    const ctx = await ctxWithJudgment(DEFAULT_VERIFY_GATE)
    await expect(judgeCdnOrUpdate(ctx, CLOUDFLARE_C2, [], '')).resolves.toBe(true)
  })

  it('allows below the gate', async () => {
    const ctx = await ctxWithJudgment(0.45)
    await expect(judgeCdnOrUpdate(ctx, CLOUDFLARE_C2, [], '')).resolves.toBe(false)
  })

  it('honors a caller-supplied gate', async () => {
    const ctx = await ctxWithJudgment(0.45)
    await expect(judgeCdnOrUpdate(ctx, CLOUDFLARE_C2, [], '', 0.4)).resolves.toBe(true)
  })

  it('returns undefined when the backend fails, so the shipped rule stands', async () => {
    const ctx = await ctxWithJudgment(new Error('backend down'))
    await expect(judgeCdnOrUpdate(ctx, CLOUDFLARE_C2, [], '')).resolves.toBeUndefined()
  })
})

describe('candidateC2Addrs', () => {
  it('names each distinct non-LAN address once, in first-seen order', () => {
    expect(candidateC2Addrs({
      relationship: { src: VICTIM, dst: CLOUDFLARE_C2, dport: 443, t: '', evidence_id: 'e' },
      endpoints: [
        { addr: CLOUDFLARE_C2, role: 'c2', because: 'the payload host' },
        { addr: '8.8.4.4', role: 'unknown', because: 'also named' },
      ],
    })).toEqual([CLOUDFLARE_C2, '8.8.4.4'])
  })

  it('omits LAN addresses, which can never be the C2', () => {
    expect(candidateC2Addrs({
      relationship: { src: VICTIM, dst: '10.9.8.1', dport: 445, t: '', evidence_id: 'e' },
      endpoints: [],
    })).toEqual([])
  })

  it('tolerates a request whose parts are missing or not strings', () => {
    expect(candidateC2Addrs({ relationship: undefined, endpoints: undefined } as never)).toEqual([])
    expect(candidateC2Addrs({
      relationship: { src: 7, dst: null } as never,
      endpoints: [{ addr: 9 } as never, undefined as never],
    })).toEqual([])
  })
})

describe('the bind gate', () => {
  const request = {
    relationship: {
      src: VICTIM, dst: CLOUDFLARE_C2, dport: 443,
      t: '2026-09-10 00:00:00', evidence_id: 'capture.pcap',
    },
    endpoints: [
      { addr: VICTIM, role: 'victim' as const, because: 'sole LAN host' },
      { addr: CLOUDFLARE_C2, role: 'c2' as const, because: 'the payload host' },
    ],
  }
  const identities = [hostname('kernel-87.com', CLOUDFLARE_C2)]

  it('refuses a Cloudflare-fronted C2 with no verdict, as it does today', () => {
    const resolved = resolveBind(request, identities, '')
    expect(resolved.ok).toBe(false)
  })

  it('allows that bind when the verifier says the destination is not benign', () => {
    const resolved = resolveBind(request, identities, '', new Map([[CLOUDFLARE_C2, false]]))
    expect(resolved.ok).toBe(true)
  })

  it('still refuses when the verifier agrees the destination is benign', () => {
    const resolved = resolveBind(request, identities, '', new Map([[CLOUDFLARE_C2, true]]))
    expect(resolved.ok).toBe(false)
  })

  it('leaves the shipped rule in force for an address with no verdict', () => {
    const resolved = resolveBind(request, identities, '', new Map([['9.9.9.9', false]]))
    expect(resolved.ok).toBe(false)
  })
})

describe('the model-facing rule', () => {
  it('refuses a CDN destination outright with no verifier mounted', () => {
    expect(methodologySection(false)).toContain(C2_ROLE_RULE)
    expect(methodologySection(false)).not.toContain('propose the bind and cite the hostname')
  })

  it('invites the bind and names the evidence when a verifier is mounted', () => {
    const text = methodologySection(true)
    expect(text).toContain(C2_ROLE_RULE_VERIFIED)
    expect(text).not.toContain(C2_ROLE_RULE)
    // The LAN half is exact arithmetic and must survive the softening.
    expect(text).toContain('Role c2 cannot be a LAN address.')
  })
})

describe('victim hostname projection', () => {
  const bind = {
    relationship: { src: VICTIM, dst: CLOUDFLARE_C2, dport: 443, t: '', evidence_id: 'e' },
    endpoints: [
      { addr: VICTIM, role: 'victim' as const, because: 'sole LAN host' },
      { addr: CLOUDFLARE_C2, role: 'c2' as const, because: 'the payload host' },
    ],
  }

  it('omits a public DNS name the victim merely resolved', () => {
    // `kernel-87.com` is evidenced on the non-LAN address it resolved to.
    const evidence = `${VICTIM} -> ${CLOUDFLARE_C2} dns.qry.name == kernel-87.com`
    const slot = projectVictimSlot(bind, [hostname('kernel-87.com', CLOUDFLARE_C2)], evidence)
    expect(slot?.hostname).toBeUndefined()
  })

  it('keeps a workstation name evidenced on the victim itself', () => {
    const evidence = `${VICTIM} nbns.name == DESKTOP-6XHCAG4`
    const slot = projectVictimSlot(bind, [hostname('DESKTOP-6XHCAG4', VICTIM)], evidence)
    expect(slot?.hostname).toBe('DESKTOP-6XHCAG4')
  })
})

describe('identity value plausibility', () => {
  it('drops a display-filter operator harvested as a user', () => {
    expect(normalizeIdentityValue('user', '==')).toBeUndefined()
    expect(normalizeIdentityValue('user', '&&')).toBeUndefined()
  })

  it('drops a prose word harvested as a hostname', () => {
    expect(normalizeIdentityValue('hostname', 'only')).toBeUndefined()
    expect(normalizeIdentityValue('hostname', 'Host')).toBeUndefined()
    expect(normalizeIdentityValue('hostname', 'browser')).toBeUndefined()
  })

  // Pre-existing and deliberately untouched: `PROTOCOL_FIELD_VALUE` rejects any
  // `word.word` user, so a real `first.last` account never enters the ledger.
  // Widening it would admit tshark field names like `ip.src`, so it stays.
  it('still rejects a dotted user, which a tshark field name also looks like', () => {
    expect(normalizeIdentityValue('user', 'glen.powers')).toBeUndefined()
  })

  it('keeps real identities, including names that merely contain a prose word', () => {
    expect(normalizeIdentityValue('hostname', 'DESKTOP-6XHCAG4')).toBe('desktop-6xhcag4')
    expect(normalizeIdentityValue('hostname', 'only-dc-01')).toBe('only-dc-01')
    expect(normalizeIdentityValue('user', 'mark')).toBe('mark')
    expect(normalizeIdentityValue('full_name', 'Glen Powers')).toBe('Glen Powers')
  })
})

describe('the bind tool description', () => {
  it('states the hard rule with no verifier mounted', () => {
    expect(bindRelationshipDescription(false)).toContain(C2_ROLE_RULE)
  })

  it('invites the bind when a verifier is mounted', () => {
    const text = bindRelationshipDescription(true)
    expect(text).toContain(C2_ROLE_RULE_VERIFIED)
    expect(text).not.toContain(C2_ROLE_RULE)
  })
})

describe('published victim slot', () => {
  const published = {
    entity_id: '10.8.6.101', ip: '10.8.6.101', mac: '00:08:02:1c:47:ae',
    hostname: 'DESKTOP-6XHCAG4', user: 'mark',
  }

  it('keeps a submitted hostname and user the re-projection cannot supply', () => {
    // The ledger has no donated hostname or user, so a later bind re-projects
    // only ip and mac. Before this merge the accepted values were dropped.
    const projected = { entity_id: '10.8.6.101', ip: '10.8.6.101', mac: '00:08:02:1c:47:ae' }
    expect(keepPublishedSlotFields(published, projected)).toEqual(published)
  })

  it('lets the projection win on a field it does supply', () => {
    const projected = { entity_id: '10.8.6.101', user: 'someone-else' }
    expect(keepPublishedSlotFields(published, projected).user).toBe('someone-else')
  })

  it('leaves a slot for a different entity untouched', () => {
    const other = { entity_id: '10.9.9.9', hostname: 'OTHER-PC' }
    expect(keepPublishedSlotFields(published, other)).toEqual(published)
  })
})

describe('destination enumeration', () => {
  const V = '10.9.10.26'
  const C2 = '165.22.199.85'
  const DELIVERY = '104.21.74.178'
  // One line is one conversation, as tshark's conv,ip table renders it.
  const CONV = [
    `${V} <-> ${C2}    1189 85 kB   1536 1923 kB   2725 2009 kB`,
    `${V} <-> ${DELIVERY}  470 619 kB  133 10 kB   603 629 kB`,
    `${V} <-> 10.9.10.1    5 531 bytes  5 371 bytes  10 902 bytes`,
  ].join('\n')
  const bind = {
    relationship: { src: V, dst: C2, dport: 80, t: '', evidence_id: 'e' },
    endpoints: [
      { addr: V, role: 'victim' as const, because: 'sole LAN host' },
      { addr: C2, role: 'c2' as const, because: 'tasking and exfil' },
    ],
  }

  it('names every non-LAN peer of the victim and omits the gateway', () => {
    expect(wanPeersOfVictim(CONV, V)).toEqual([C2, DELIVERY])
  })

  it('flags a destination the close never mentions', () => {
    expect(undisposedDestinations({ what: 'victim talked to the C2' }, bind, CONV))
      .toEqual([DELIVERY])
  })

  it('accepts a destination named by address in the narrative', () => {
    expect(undisposedDestinations({ what: `also fetched from ${DELIVERY}` }, bind, CONV))
      .toEqual([])
  })

  it('accepts a destination named by an evidenced hostname', () => {
    const identities = [hostname('kernel-87.com', DELIVERY)]
    const evidence = `${CONV}\n${DELIVERY} kernel-87.com`
    expect(undisposedDestinations(
      { what: 'payload came from kernel-87.com' }, bind, evidence, identities,
    )).toEqual([])
  })

  it('accepts a destination the bind gave a role, without narrative text', () => {
    const roled = {
      ...bind,
      endpoints: [...bind.endpoints, { addr: DELIVERY, role: 'unknown' as const, because: 'payload host' }],
    }
    expect(undisposedDestinations({ what: 'x' }, roled, CONV)).toEqual([])
  })

  it('skips a destination the verifier cleared as background', () => {
    expect(undisposedDestinations({ what: 'x' }, bind, CONV, [], new Set([DELIVERY])))
      .toEqual([])
  })

  it('requires nothing when no bind exists', () => {
    expect(undisposedDestinations({ what: 'x' }, undefined, CONV)).toEqual([])
  })

  it('renders a denial that names the address and what the capture called it', () => {
    const identities = [hostname('kernel-87.com', DELIVERY)]
    const reason = undisposedDenyReason([DELIVERY], identities, `${DELIVERY} kernel-87.com`)
    expect(reason).toContain(DELIVERY)
    expect(reason).toContain('kernel-87.com')
    expect(reason).toContain('benign background')
  })
})

describe('droppableDestinations', () => {
  it('clears nothing when no judgment provider is mounted', async () => {
    await expect(droppableDestinations(new Context(), ['1.2.3.4'], [], ''))
      .resolves.toEqual(new Set())
  })

  it('clears a destination scored below the drop gate', async () => {
    const ctx = await ctxWithJudgment(0.02)
    await expect(droppableDestinations(ctx, ['1.2.3.4'], [], '')).resolves.toEqual(new Set(['1.2.3.4']))
  })

  it('keeps a destination at or above the drop gate', async () => {
    const ctx = await ctxWithJudgment(DEFAULT_DROP_GATE)
    await expect(droppableDestinations(ctx, ['1.2.3.4'], [], '')).resolves.toEqual(new Set())
  })

  it('keeps every destination when the backend fails, so the gate stays strict', async () => {
    const ctx = await ctxWithJudgment(new Error('down'))
    await expect(droppableDestinations(ctx, ['1.2.3.4'], [], '')).resolves.toEqual(new Set())
  })
})
