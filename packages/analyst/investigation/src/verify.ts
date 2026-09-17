/**
 * The bind verifier: asks `ctx.judgment` whether a destination the shipped rule
 * would refuse is really a benign service.
 *
 * The shipped rule tests a published Cloudflare or Fastly anycast prefix before
 * it consults any evidenced hostname, so an address the capture plainly names
 * `kernel-87.com` is refused as a CDN and the bind never happens. Graded against
 * the IOC lists published with seven malware-traffic-analysis.net captures, that
 * refusal is wrong 16 times out of 16 — every one an anycast-prefix refusal.
 *
 * The question is framed as "is something wrong with this bind?", one dimension
 * per failure mode, as the SDE cascade cookbook frames its verifier. Only
 * `c2_is_benign_service` is asked here; the other dimensions the seam could
 * carry stay unasked until each has evidence of its own.
 *
 * @module @deepseek-ai/dsh-investigation/verify
 */

import type { Context } from '@deepseek-ai/cordis'
import type { JudgmentState } from '@deepseek-ai/dsh-judgment'
import { hostnamesEvidencedOnIp, isCdnOrUpdateName, isCloudflareIpv4, isFastlyIpv4 } from './harvest.ts'
import type { Identity } from './types.ts'

/**
 * The verifier's single graded dimension, stated as a fault to detect rather
 * than a property to confirm: a confident yes stops the bind.
 */
export const C2_IS_BENIGN_SERVICE =
  'Something is wrong with this bind: the endpoint labelled `c2` is not attacker '
  + 'infrastructure at all. It is a content delivery network, an operating-system or '
  + 'software update service, a certificate revocation responder, an analytics or '
  + 'advertising beacon, or another ordinary service the host would contact whether or '
  + 'not it were infected. Judge the destination itself. A hosting provider, a reverse '
  + 'proxy, or a CDN sitting in front of an attacker-registered domain does not make '
  + 'the destination benign — what matters is whose service is being reached.'

/**
 * Default gate. Swept on the seven-capture corpus, 0.60 decided 76% of bind
 * proposals correctly against the shipped rule's 53%, and was better on both
 * error types at once. The cascade cookbook's own 0.7 is for a different task
 * and is not borrowed.
 */
export const DEFAULT_VERIFY_GATE = 0.6

/**
 * What the verifier judges. The prefix tests are included rather than hidden:
 * that an address sits in a published anycast range is real evidence about the
 * destination, it is simply not conclusive on its own.
 *
 * @param ip - the candidate C2 address.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text for cited-conversation names.
 * @returns the state object.
 */
export function verifyState(
  ip: string,
  identities: readonly Identity[],
  evidenceText: string,
): JudgmentState {
  const names = hostnamesEvidencedOnIp(ip, identities, evidenceText)
  return {
    endpoint_labelled_c2: {
      address: ip,
      names_evidenced_in_the_capture: names,
      in_a_published_cloudflare_anycast_prefix: isCloudflareIpv4(ip),
      in_a_published_fastly_anycast_prefix: isFastlyIpv4(ip),
      a_name_matches_a_known_cdn_or_update_domain: names.some(isCdnOrUpdateName),
    },
  }
}

/**
 * Ask the verifier whether this destination is benign.
 *
 * @param ctx - context that may carry the judgment seam.
 * @param ip - the candidate C2 address.
 * @param identities - folded ledger identities.
 * @param evidenceText - tool-result text.
 * @param gate - probability at or above which the bind is refused.
 * @returns true to refuse, false to allow, or undefined when no verdict was
 *   reached — no provider mounted, or the backend failed — so the caller keeps
 *   the shipped rule rather than treating silence as permission.
 */
export async function judgeCdnOrUpdate(
  ctx: Context,
  ip: string,
  identities: readonly Identity[],
  evidenceText: string,
  gate: number = DEFAULT_VERIFY_GATE,
): Promise<boolean | undefined> {
  const judgment = ctx.get('judgment')
  if (judgment === undefined) return undefined
  try {
    const answer = await judgment.noul(
      verifyState(ip, identities, evidenceText),
      C2_IS_BENIGN_SERVICE,
    )
    return answer.noul >= gate
  } catch {
    // A judgment outage must not change a bind's outcome: fall back to the
    // shipped rule rather than refusing or allowing on a failed call.
    return undefined
  }
}
