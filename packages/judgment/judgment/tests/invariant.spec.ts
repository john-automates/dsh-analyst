import { Context } from '@deepseek-ai/cordis'
import InvariantRegistry from '@deepseek-ai/dsh-invariants'
import { describe, expect, it } from 'vitest'
import * as Companion from '../src/invariant.ts'

describe('judgment invariant companion', () => {
  it('reserves package ownership and installs no runtime check', async () => {
    const ctx = new Context()
    await ctx.plugin(InvariantRegistry, { enabled: true })
    await expect(ctx.plugin(Companion).then(() => undefined)).resolves.toBeUndefined()
    expect(Companion.inject).toEqual(['invariants'])
  })
})
