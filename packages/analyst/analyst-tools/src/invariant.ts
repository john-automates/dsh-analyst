/**
 * Package-owned invariant companion for `@deepseek-ai/dsh-analyst-tools`.
 * @module @deepseek-ai/dsh-analyst-tools/invariant
 */

/* jscpd:ignore-start */
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = '@deepseek-ai/dsh-analyst-tools'

/** Cordis companion plugin name. */
export const name = 'analyst-tools-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: the package registers tools only; durable identity,
 * hunt, and report events belong to `@deepseek-ai/dsh-investigation`.
 */
const install: InvariantInstaller = () => {}

/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install))
/* jscpd:ignore-end */
