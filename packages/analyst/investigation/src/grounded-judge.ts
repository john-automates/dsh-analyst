/**
 * The judgment rung of the groundedness cascade.
 *
 * {@link grounded.ts} decides by occurrence, which is exact and free. What it
 * cannot decide is whether a flagged token was ever *meant* as an indicator.
 * The regex-only version of this check got that wrong in both directions: it
 * called `keychain-2.db`, `notestore.sqlite` and the username `glen.powers`
 * fabricated addresses, and it read `browser.host` as an indicator only because
 * `host` happens to be a public suffix.
 *
 * So this asks one narrow question, and only about atoms the exact check
 * already flagged. That ordering is the safety property: a `no` releases a
 * false positive, a `yes` confirms a refusal the deterministic rung had already
 * reached. Judgment can shrink the deny list and can never grow it, so a
 * miscalibrated model degrades this gate toward the behaviour it has today
 * rather than toward refusing correct reports.
 *
 * Cost follows from the same ordering. A clean close asks nothing at all; a
 * flagged one asks about a handful of atoms at roughly $0.00003 each, against
 * an investigation that costs $0.04.
 */
import type { Context } from '@deepseek-ai/cordis'
import type { JudgmentState } from '@deepseek-ai/dsh-judgment'

/**
 * Probability at or above which a flagged atom is treated as a real indicator
 * claim and the refusal stands.
 *
 * Set high on purpose. The question is asked only about atoms already flagged,
 * so the model is being given a chance to overturn an exact result; it should
 * have to be confident to let one through, and unsure should leave the refusal
 * in place. This is not the bind verifier's 0.6, which arbitrates between two
 * live hypotheses.
 */
export const DEFAULT_CLAIM_GATE = 0.5

/**
 * Whether the atom is asserted as a network or host indicator.
 *
 * Stated so that "yes" is unambiguous, and naming the alternatives explicitly
 * because the false positives seen in practice are all of one shape: a
 * filename, a bundle identifier, or an account that merely contains a dot.
 */
export const ATOM_IS_AN_INDICATOR_CLAIM = {
  instructions:
    'In this report, the token is asserted as a network or host indicator — a '
    + 'destination address, a domain or DNS name the host contacted, or the name '
    + 'of a machine involved in the incident. It is NOT an indicator when it is a '
    + 'file name or path, a software bundle identifier such as com.apple.accountsd, '
    + 'a registry key, a protocol field name, a version string, or a person or '
    + 'account name that merely happens to contain a dot.',
} as const

/**
 * The state the question is asked about.
 * @param atom - the flagged atom.
 * @param args - submitted `case_report` arguments.
 * @returns the state object.
 */
export function claimState(atom: string, args: unknown): JudgmentState {
  const blob = JSON.stringify(args ?? {})
  const at = blob.toLowerCase().indexOf(atom.toLowerCase())
  return {
    token: atom,
    // A window rather than the whole report: the question is about how this
    // token is used, and the surrounding sentence is what says so.
    how_the_report_uses_it: at < 0
      ? blob.slice(0, 400)
      : blob.slice(Math.max(0, at - 200), at + atom.length + 200),
  }
}

/**
 * Narrow a deny list to the atoms that are really indicator claims.
 *
 * @param ctx - context that may carry the judgment seam.
 * @param atoms - atoms the exact check flagged as unevidenced.
 * @param args - submitted `case_report` arguments.
 * @param gate - probability at or above which the refusal stands.
 * @returns the atoms still refused. With no judgment provider mounted, or on a
 *   backend failure, the input is returned unchanged: silence is never taken as
 *   permission, exactly as {@link judgeCdnOrUpdate} treats an outage.
 */
export async function narrowToIndicatorClaims(
  ctx: Context,
  atoms: readonly string[],
  args: unknown,
  gate: number = DEFAULT_CLAIM_GATE,
): Promise<string[]> {
  const judgment = ctx.get('judgment')
  if (judgment === undefined || atoms.length === 0) return [...atoms]
  const kept: string[] = []
  for (const atom of atoms) {
    try {
      const answer = await judgment.noul(claimState(atom, args), ATOM_IS_AN_INDICATOR_CLAIM)
      if (answer.noul >= gate) kept.push(atom)
    } catch {
      // One failed call must not release an atom the exact rung refused.
      kept.push(atom)
    }
  }
  return kept
}
