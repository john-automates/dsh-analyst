import { Context } from '@deepseek-ai/cordis'
import JudgmentRuntime, { type JudgmentProvider } from '@deepseek-ai/dsh-judgment/src/index.ts'
import { describe, expect, it } from 'vitest'
import {
  C2_IS_BENIGN_SERVICE,
  DEFAULT_VERIFY_GATE,
  judgeCdnOrUpdate,
  verifyState,
} from '@deepseek-ai/dsh-investigation/src/verify.ts'
import { candidateC2Addrs, resolveBind } from '@deepseek-ai/dsh-investigation'
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
