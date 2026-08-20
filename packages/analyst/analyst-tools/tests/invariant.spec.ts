import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import InvariantRegistry from '@deepseek-ai/dsh-invariants'
import * as AnalystToolsInvariant from '../src/invariant.ts'

describe('analyst-tools invariant', () => {
  it('registers an empty companion that owns the package name', async () => {
    const ctx = new Context()
    await ctx.plugin(InvariantRegistry, { enabled: true })
    await ctx.plugin(AnalystToolsInvariant)
    expect(AnalystToolsInvariant.name).toBe('analyst-tools-invariant')
    expect(AnalystToolsInvariant.inject).toEqual(['invariants'])
  })
})
