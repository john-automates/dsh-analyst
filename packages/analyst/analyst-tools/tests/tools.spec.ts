import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import { CallId } from '@deepseek-ai/dsh-llm'
import { Session, SessionId } from '@deepseek-ai/dsh-session'
import type { Agent } from '@deepseek-ai/dsh-agent'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { type ToolExecutionToken } from '@deepseek-ai/dsh-tools'
import Investigation from '@deepseek-ai/dsh-investigation'
import * as tools from '../src/index.ts'
import { clipOutput, formatFieldRows, helperFailureText, runHelper } from '../src/index.ts'

const signal = new AbortController().signal
let root: string | undefined

afterEach(async () => {
  if (root !== undefined) await rm(root, { recursive: true, force: true })
  root = undefined
})

function agent(id = 'analyst-1'): Agent {
  const session = Session.create(SessionId(id))
  return { id: SessionId(id), session } as unknown as Agent
}

async function script(dir: string, name: string, body: string): Promise<string> {
  const path = join(dir, name)
  await writeFile(path, `#!/bin/sh\n${body}\n`)
  await chmod(path, 0o755)
  return path
}

async function setup(over: Partial<tools.Config> = {}): Promise<{
  ctx: Context
  caseDir: string
  owner: Agent
  toolsFiber: { dispose: () => Promise<void> }
}> {
  root = await mkdtemp(join(tmpdir(), 'dsh-analyst-tools-'))
  const caseDir = join(root, 'case')
  await mkdir(join(caseDir, 'evidence'), { recursive: true })
  await writeFile(join(caseDir, 'evidence', 'a.pcap'), 'pcap')
  await writeFile(join(caseDir, 'auth.log'), 'line1\nline2\nline3\n')
  const tsharkBin = await script(root, 'tshark', [
    'for arg in "$@"; do if [ "$arg" = "-q" ]; then echo "tshark-info"; exit 0; fi; done',
    'echo "alice\tbob"',
  ].join('\n'))
  const capinfosBin = await script(root, 'capinfos', 'echo "capinfos-ok"')
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(Investigation, { caseDir })
  const toolsFiber = await ctx.plugin(tools, {
    maxOutputChars: 32_000,
    commandTimeoutMs: 5_000,
    tsharkBin,
    capinfosBin,
    ...over,
  })
  return { ctx, caseDir, owner: agent(), toolsFiber }
}

function text(result: { content: { type: string; text?: string }[] }): string {
  return result.content.filter(block => block.type === 'text').map(block => block.text).join('')
}

describe('analyst tools', () => {
  it('has the namespace-plugin export shape (no stray default)', () => {
    expect('default' in tools).toBe(false)
    expect(tools.name).toBe('analyst-tools')
    expect(tools.inject).toEqual(['tools', 'investigation'])
    const loader = Object.create(Loader.prototype) as Loader
    const unwrapped = loader.unwrapExports(tools) as Record<string, unknown>
    expect(unwrapped).toBe(tools)
    expect(typeof unwrapped.apply).toBe('function')
  })

  it('clips output and labels tshark field rows', () => {
    expect(clipOutput('abc', 10)).toBe('abc')
    expect(clipOutput('abcdefghij', 4)).toBe('abcd\n[truncated: 6 more characters]')
    expect(formatFieldRows([], 'raw')).toBe('raw')
    expect(formatFieldRows(['kerberos.CNameString', 'other'], 'alice\tbob\n')).toBe(
      'kerberos.CNameString: alice\tother: bob',
    )
    expect(formatFieldRows(['kerberos.CNameString', 'other'], 'alice\n')).toBe(
      'kerberos.CNameString: alice\tother: ',
    )
    expect(helperFailureText({})).toBe('')
    expect(helperFailureText({ stdout: 1, stderr: 2 })).toBe('')
    expect(helperFailureText({ stdout: 'out' })).toBe('out')
    expect(helperFailureText({ stdout: 'out', stderr: 'err' })).toBe('out\nerr')
    expect(new tools.Config({})).toMatchObject({
      maxOutputChars: 32_000,
      commandTimeoutMs: 60_000,
      tsharkBin: 'tshark',
      capinfosBin: 'capinfos',
    })
  })

  it('summarizes a pcap with capinfos and falls back to tshark', async () => {
    const { ctx, owner } = await setup()
    const info = await ctx.tools.execute({
      signal, callId: CallId('info'), name: 'pcap_info', arguments: { path: 'evidence/a.pcap' }, agent: owner,
    })
    expect(info.isError).toBe(false)
    expect(text(info)).toContain('capinfos-ok')
    const missingCap = await setup({ capinfosBin: join(root!, 'missing-capinfos') })
    const fallback = await missingCap.ctx.tools.execute({
      signal, callId: CallId('info2'), name: 'pcap_info', arguments: { path: 'evidence/a.pcap' }, agent: missingCap.owner,
    })
    expect(text(fallback)).toContain('tshark-info')
    await missingCap.ctx.fiber.dispose()
  })

  it('filters a pcap, rejects invalid fields, and reads logs', async () => {
    const { ctx, owner, caseDir } = await setup()
    const filtered = await ctx.tools.execute({
      signal,
      callId: CallId('filter'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: 'kerberos.CNameString',
        fields: ['kerberos.CNameString', 'samr.samr_UserInfo21.account_name'],
      },
      agent: owner,
    })
    expect(filtered.isError).toBe(false)
    expect(text(filtered)).toContain('kerberos.CNameString: alice')
    const invalid = await ctx.tools.execute({
      signal,
      callId: CallId('bad'),
      name: 'pcap_filter',
      arguments: { path: 'evidence/a.pcap', fields: ['ldap.sAMAccountName'] },
      agent: owner,
    })
    expect(invalid.isError).toBe(true)
    expect(text(invalid)).toContain('ldap.sAMAccountName')
    const logs = await ctx.tools.execute({
      signal,
      callId: CallId('logs'),
      name: 'logs',
      arguments: { path: join(caseDir, 'auth.log'), start_line: 2, max_lines: 1 },
      agent: owner,
    })
    expect(text(logs)).toBe('line2')
    const whole = await ctx.tools.execute({
      signal, callId: CallId('logs-all'), name: 'logs', arguments: { path: 'auth.log' }, agent: owner,
    })
    expect(text(whole)).toBe('line1\nline2\nline3\n')
    const raw = await ctx.tools.execute({
      signal, callId: CallId('raw'), name: 'pcap_filter', arguments: { path: 'evidence/a.pcap' }, agent: owner,
    })
    expect(text(raw)).toContain('alice')
    const missing = await ctx.tools.execute({
      signal, callId: CallId('miss'), name: 'logs', arguments: { path: 'evidence/missing.pcap' }, agent: owner,
    })
    expect(missing.isError).toBe(true)
    const outside = await ctx.tools.execute({
      signal, callId: CallId('out'), name: 'logs', arguments: { path: '/etc/passwd' }, agent: owner,
    })
    expect(outside.isError).toBe(true)
    expect(text(outside)).toContain('outside the case directory')
  })

  it('spawns tshark -e when fields is the string kerberos.CNameString', async () => {
    const binDir = await mkdtemp(join(tmpdir(), 'dsh-tshark-argv-'))
    const tsharkBin = await script(binDir, 'tshark', [
      'printf "%s\\n" "$@" >> argv.log',
      'echo brolf',
    ].join('\n'))
    const { ctx, owner, caseDir } = await setup({ tsharkBin })
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('cname-string'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: 'kerberos.CNameString',
        fields: 'kerberos.CNameString',
      },
      agent: owner,
    })
    expect(result.isError).toBe(false)
    expect(text(result)).toBe('kerberos.CNameString: brolf')
    const argv = (await readFile(join(caseDir, 'argv.log'), 'utf8')).trim().split('\n')
    expect(argv).toContain('-e')
    expect(argv.filter((_, index) => argv[index - 1] === '-e')).toContain('kerberos.CNameString')
    const invalid = await ctx.tools.execute({
      signal,
      callId: CallId('cname-invalid'),
      name: 'pcap_filter',
      arguments: { path: 'evidence/a.pcap', fields: 'ldap.sAMAccountName' },
      agent: owner,
    })
    expect(invalid.isError).toBe(true)
    expect(text(invalid)).toContain('ldap.sAMAccountName')
    expect(text(invalid)).not.toMatch(/INVALID_ARGS|invalid arguments/i)
    await rm(binDir, { recursive: true, force: true })
  })

  it('spawns tshark -Y with wrapping quotes stripped from display_filter', async () => {
    const binDir = await mkdtemp(join(tmpdir(), 'dsh-tshark-filter-argv-'))
    const tsharkBin = await script(binDir, 'tshark', [
      'printf "%s\\n" "$@" > argv.log',
      'echo rows',
    ].join('\n'))
    const { ctx, owner, caseDir } = await setup({ tsharkBin })
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('quoted-filter'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: '"ip.addr == 1.2.3.4"',
      },
      agent: owner,
    })
    expect(result.isError).toBe(false)
    const argv = (await readFile(join(caseDir, 'argv.log'), 'utf8')).trim().split('\n')
    expect(argv).toContain('-Y')
    expect(argv[argv.indexOf('-Y') + 1]).toBe('ip.addr == 1.2.3.4')
    const invalid = await ctx.tools.execute({
      signal,
      callId: CallId('quoted-invalid'),
      name: 'pcap_filter',
      arguments: {
        path: 'evidence/a.pcap',
        display_filter: "'llmnr or nbns or browser'",
        fields: 'ldap.sAMAccountName',
      },
      agent: owner,
    })
    expect(invalid.isError).toBe(true)
    expect(text(invalid)).toContain('ldap.sAMAccountName')
    expect(text(invalid)).not.toMatch(/INVALID_ARGS|invalid arguments/i)
    await rm(binDir, { recursive: true, force: true })
  })

  it('requires bind_relationship before case_report and projects who/where from the victim', async () => {
    const { ctx, owner } = await setup()
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '10.0.10.2', label: 'IP' })
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '198.51.100.80', label: 'IP' })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC', entity_id: '10.0.10.2',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'lan-host', label: 'hostname', entity_id: '10.0.10.2',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'mac', value: '02:00:00:00:00:0b', label: 'MAC', entity_id: '10.0.10.3',
    })
    const claims = {
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      why: 'c2',
      how: 'https',
    }
    const unbound = await ctx.tools.execute({
      signal, callId: CallId('report-unbound'), name: 'case_report', arguments: claims, agent: owner,
    })
    expect(unbound.isError).toBe(true)
    expect(text(unbound)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const bind = await ctx.tools.execute({
      signal,
      callId: CallId('bind'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2',
        dst: '198.51.100.80',
        dport: 443,
        t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: [
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80 in evidence conv-1' },
          { addr: '198.51.100.80', because: 'cue/observation address' },
          { addr: '10.0.10.3', role: 'distractor', because: 'idle LAN workstation' },
        ],
      },
      agent: owner,
    })
    expect(bind.isError).toBe(false)
    expect(text(bind)).toContain('victim 10.0.10.2')
    expect(text(bind)).toContain('c2 198.51.100.80')
    const inverted = await ctx.tools.execute({
      signal,
      callId: CallId('report-c2'),
      name: 'case_report',
      arguments: { ...claims, who: { entity_id: '198.51.100.80' } },
      agent: owner,
    })
    expect(inverted.isError).toBe(true)
    expect(text(inverted)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const result = await ctx.tools.execute({
      signal, callId: CallId('report'), name: 'case_report', arguments: claims, agent: owner,
    })
    expect(result.isError).toBe(false)
    expect(ctx.investigation.report(owner.session)).toEqual({
      who: { entity_id: '10.0.10.2', ip: '10.0.10.2', mac: '02:00:00:00:00:0a', hostname: 'lan-host' },
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      where: { entity_id: '10.0.10.2', ip: '10.0.10.2', mac: '02:00:00:00:00:0a', hostname: 'lan-host' },
      why: 'c2',
      how: 'https',
    })
    expect(text(result)).toContain('Who: 10.0.10.2 02:00:00:00:00:0a lan-host')
    expect(text(result)).not.toContain('02:00:00:00:00:0b')
    expect(ctx.tools.get('bind_relationship')?.presentCall?.({
      src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'e', endpoints: [],
    })?.title).toBe('Bind conversation')
    expect(ctx.tools.get('bind_relationship')?.output.render({}, {
      src: '10.0.10.2',
      dst: '198.51.100.80',
      dport: 443,
      t: '2026-08-21T00:00:00Z',
      evidence_id: 'conv-1',
      endpoints: [
        { addr: '10.0.10.2', role: 'victim', because: 'conversation' },
        { addr: '198.51.100.80', role: 'c2', because: 'cue' },
      ],
    })).toEqual([
      expect.objectContaining({ type: 'text', text: expect.stringContaining('Conversation bind') }),
    ])
    const hostOnly = await setup()
    const hostBind = await hostOnly.ctx.tools.execute({
      signal,
      callId: CallId('bind-host'),
      name: 'bind_relationship',
      arguments: {
        src: 'lan-host',
        dst: '198.51.100.80',
        dport: 443,
        t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: [
          { addr: 'lan-host', role: 'victim', because: 'lan-host talking to 198.51.100.80 in evidence conv-1' },
        ],
      },
      agent: hostOnly.owner,
    })
    expect(hostBind.isError).toBe(false)
    const hostReport = await hostOnly.ctx.tools.execute({
      signal, callId: CallId('report-host'), name: 'case_report', arguments: claims, agent: hostOnly.owner,
    })
    expect(hostReport.isError).toBe(false)
    expect(text(hostReport)).toContain('Who: lan-host')
    expect(hostOnly.ctx.investigation.report(hostOnly.owner.session)?.who).toEqual({ entity_id: 'lan-host' })
    await hostOnly.ctx.fiber.dispose()
  })

  it('projects case_report who from a victim-row user handle after a live bind', async () => {
    const { ctx, owner } = await setup()
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '10.0.10.2', label: 'IP' })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'user', value: 'lan-user', label: 'user', entity_id: '10.0.10.2',
    })
    const claims = {
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      why: 'c2',
      how: 'https',
    }
    const unbound = await ctx.tools.execute({
      signal,
      callId: CallId('report-user-unbound'),
      name: 'case_report',
      arguments: { ...claims, who: { entity_id: 'lan-user' }, where: { entity_id: '10.0.10.2' } },
      agent: owner,
    })
    expect(unbound.isError).toBe(true)
    expect(text(unbound)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const bind = await ctx.tools.execute({
      signal,
      callId: CallId('bind-user-row'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2',
        dst: '198.51.100.80',
        dport: 443,
        t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: [
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80 in evidence conv-1' },
        ],
      },
      agent: owner,
    })
    expect(bind.isError).toBe(false)
    const inverted = await ctx.tools.execute({
      signal,
      callId: CallId('report-user-inverted'),
      name: 'case_report',
      arguments: { ...claims, who: { entity_id: '198.51.100.80' } },
      agent: owner,
    })
    expect(inverted.isError).toBe(true)
    expect(text(inverted)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('report-user-row'),
      name: 'case_report',
      arguments: { ...claims, who: { entity_id: 'lan-user' }, where: { entity_id: '10.0.10.2' } },
      agent: owner,
    })
    expect(result.isError).toBe(false)
    expect(ctx.investigation.report(owner.session)).toEqual({
      who: { entity_id: '10.0.10.2', ip: '10.0.10.2', user: 'lan-user' },
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      where: { entity_id: '10.0.10.2', ip: '10.0.10.2', user: 'lan-user' },
      why: 'c2',
      how: 'https',
    })
    expect(text(result)).toContain('Who: 10.0.10.2 lan-user')
  })

  it('closes case_report when who/where are JSON strings with entity_id after a live bind', async () => {
    const { ctx, owner } = await setup()
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '10.0.10.2', label: 'IP' })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'user', value: 'lan-user', label: 'user', entity_id: '10.0.10.2',
    })
    const claims = {
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      why: 'c2',
      how: 'https',
    }
    const stringSlots = {
      ...claims,
      who: JSON.stringify({ entity_id: 'lan-user' }),
      where: JSON.stringify({ entity_id: '10.0.10.2' }),
    }
    const unbound = await ctx.tools.execute({
      signal,
      callId: CallId('report-json-unbound'),
      name: 'case_report',
      arguments: stringSlots,
      agent: owner,
    })
    expect(unbound.isError).toBe(true)
    expect(text(unbound)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const bind = await ctx.tools.execute({
      signal,
      callId: CallId('bind-json-slots'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2',
        dst: '198.51.100.80',
        dport: 443,
        t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: [
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80 in evidence conv-1' },
        ],
      },
      agent: owner,
    })
    expect(bind.isError).toBe(false)
    const inverted = await ctx.tools.execute({
      signal,
      callId: CallId('report-json-inverted'),
      name: 'case_report',
      arguments: { ...claims, who: JSON.stringify({ entity_id: '198.51.100.80' }) },
      agent: owner,
    })
    expect(inverted.isError).toBe(true)
    expect(text(inverted)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('report-json-slots'),
      name: 'case_report',
      arguments: stringSlots,
      agent: owner,
    })
    expect(result.isError).toBe(false)
    expect(ctx.investigation.report(owner.session)).toEqual({
      who: { entity_id: '10.0.10.2', ip: '10.0.10.2', user: 'lan-user' },
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      where: { entity_id: '10.0.10.2', ip: '10.0.10.2', user: 'lan-user' },
      why: 'c2',
      how: 'https',
    })
    expect(text(result)).toContain('Who: 10.0.10.2 lan-user')
  })

  it('closes case_report when who/where are victim-row handle strings after a live bind', async () => {
    const { ctx, owner } = await setup()
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '10.0.10.2', label: 'IP' })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'user', value: 'lan-user', label: 'user', entity_id: '10.0.10.2',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'full_name', value: 'Lan User', label: 'full name', entity_id: '10.0.10.2',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'hostname', value: 'lan-host', label: 'hostname', entity_id: '10.0.10.2',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'user', value: 'idle-user', label: 'user', entity_id: '10.0.10.3',
    })
    const claims = {
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      why: 'c2',
      how: 'https',
    }
    const handleSlots = {
      ...claims,
      who: 'lan-user (Lan User)',
      where: '10.0.10.2 (lan-host)',
    }
    const unbound = await ctx.tools.execute({
      signal,
      callId: CallId('report-handle-unbound'),
      name: 'case_report',
      arguments: handleSlots,
      agent: owner,
    })
    expect(unbound.isError).toBe(true)
    expect(text(unbound)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const bind = await ctx.tools.execute({
      signal,
      callId: CallId('bind-handle-slots'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2',
        dst: '198.51.100.80',
        dport: 443,
        t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: [
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80 in evidence conv-1' },
        ],
      },
      agent: owner,
    })
    expect(bind.isError).toBe(false)
    const inverted = await ctx.tools.execute({
      signal,
      callId: CallId('report-handle-c2'),
      name: 'case_report',
      arguments: { ...claims, who: '198.51.100.80' },
      agent: owner,
    })
    expect(inverted.isError).toBe(true)
    expect(text(inverted)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const distractor = await ctx.tools.execute({
      signal,
      callId: CallId('report-handle-distractor'),
      name: 'case_report',
      arguments: { ...claims, who: 'idle-user' },
      agent: owner,
    })
    expect(distractor.isError).toBe(true)
    expect(text(distractor)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const prose = await ctx.tools.execute({
      signal,
      callId: CallId('report-handle-prose'),
      name: 'case_report',
      arguments: { ...claims, who: 'the workstation on the LAN' },
      agent: owner,
    })
    expect(prose.isError).toBe(true)
    expect(text(prose)).toContain('unbound: assign victim vs c2 on the cited conversation.')
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('report-handle-slots'),
      name: 'case_report',
      arguments: handleSlots,
      agent: owner,
    })
    expect(result.isError).toBe(false)
    expect(ctx.investigation.report(owner.session)).toEqual({
      who: {
        entity_id: '10.0.10.2',
        ip: '10.0.10.2',
        hostname: 'lan-host',
        user: 'lan-user',
        full_name: 'Lan User',
      },
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      where: {
        entity_id: '10.0.10.2',
        ip: '10.0.10.2',
        hostname: 'lan-host',
        user: 'lan-user',
        full_name: 'Lan User',
      },
      why: 'c2',
      how: 'https',
    })
    expect(text(result)).toContain('Who: 10.0.10.2 lan-host lan-user Lan User')
  })

  it('persists the victim row from unique unaffiliated ledger identities after a live bind', async () => {
    const { ctx, owner } = await setup()
    ctx.investigation.recordIdentity(owner.session, { kind: 'ip', value: '10.0.10.2', label: 'IP' })
    ctx.investigation.recordIdentity(owner.session, { kind: 'mac', value: '02:00:00:00:00:0a', label: 'MAC' })
    ctx.investigation.recordIdentity(owner.session, { kind: 'hostname', value: 'lan-host', label: 'hostname' })
    ctx.investigation.recordIdentity(owner.session, { kind: 'user', value: 'lan-user', label: 'user' })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'full_name', value: 'Lan User', label: 'full name',
    })
    ctx.investigation.recordIdentity(owner.session, {
      kind: 'user', value: 'idle-user', label: 'user', entity_id: '10.0.10.3',
    })
    const claims = {
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      why: 'c2',
      how: 'https',
    }
    const cueVictim = await ctx.tools.execute({
      signal,
      callId: CallId('bind-cue-victim'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2',
        dst: '198.51.100.80',
        dport: 443,
        t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: [
          { addr: '198.51.100.80', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80 in evidence conv-1' },
        ],
      },
      agent: owner,
    })
    expect(cueVictim.isError).toBe(true)
    expect(text(cueVictim)).toContain(
      'unbound: hunt LAN ip.src talking to 198.51.100.80 (ip.dst == 198.51.100.80).',
    )
    expect(ctx.investigation.hunts(owner.session)).toContainEqual({
      kind: 'other-end', subjectKind: 'ip', subject: '198.51.100.80',
    })
    expect(ctx.investigation.bind(owner.session)).toBeUndefined()
    const bind = await ctx.tools.execute({
      signal,
      callId: CallId('bind-unaffiliated'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2',
        dst: '198.51.100.80',
        dport: 443,
        t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: [
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80 in evidence conv-1' },
          { addr: '10.0.10.3', role: 'distractor', because: 'idle LAN workstation' },
        ],
      },
      agent: owner,
    })
    expect(bind.isError).toBe(false)
    const result = await ctx.tools.execute({
      signal,
      callId: CallId('report-unaffiliated'),
      name: 'case_report',
      arguments: { ...claims, who: { entity_id: 'lan-user' }, where: { entity_id: '10.0.10.2' } },
      agent: owner,
    })
    expect(result.isError).toBe(false)
    const projected = {
      entity_id: '10.0.10.2',
      ip: '10.0.10.2',
      mac: '02:00:00:00:00:0a',
      hostname: 'lan-host',
      user: 'lan-user',
      full_name: 'Lan User',
    }
    expect(ctx.investigation.report(owner.session)).toEqual({
      who: projected,
      what: 'beacon to 198.51.100.80',
      when: '2026-08-21',
      where: projected,
      why: 'c2',
      how: 'https',
    })
    expect(text(result)).toContain('Who: 10.0.10.2 02:00:00:00:00:0a lan-host lan-user Lan User')
    expect(text(result)).not.toContain('idle-user')
  })

  it('records a 5W1H case_report after a bind and rejects a non-agent caller or blank field', async () => {
    const { ctx, owner } = await setup()
    const bind = await ctx.tools.execute({
      signal,
      callId: CallId('bind-close'),
      name: 'bind_relationship',
      arguments: {
        src: '10.0.10.2',
        dst: '198.51.100.80',
        dport: 443,
        t: '2026-08-21T00:00:00Z',
        evidence_id: 'conv-1',
        endpoints: [
          { addr: '10.0.10.2', role: 'victim', because: '10.0.10.2 talking to 198.51.100.80 in evidence conv-1' },
        ],
      },
      agent: owner,
    })
    expect(bind.isError).toBe(false)
    const report = {
      what: 'account lookup',
      when: '2026-08-20',
      why: 'Kerberos then SAMR',
      how: 'QueryUserInfo',
    }
    const result = await ctx.tools.execute({
      signal, callId: CallId('report'), name: 'case_report', arguments: report, agent: owner,
    })
    expect(result.isError).toBe(false)
    expect(ctx.investigation.report(owner.session)?.who.entity_id).toBe('10.0.10.2')
    expect(ctx.investigation.report(owner.session)?.what).toBe('account lookup')
    expect(text(result)).toContain('Who: 10.0.10.2')
    const noAgent = await ctx.tools.execute({
      signal, callId: CallId('report2'), name: 'case_report', arguments: report,
    })
    expect(noAgent.isError).toBe(true)
    expect(text(noAgent)).toMatch(/owning agent session|unbound/)
    const tool = ctx.tools.get('case_report')
    if (tool === undefined) throw new Error('expected case_report')
    await expect(tool.execute(report, {
      signal,
      callId: CallId('report-direct'),
      rootCallId: CallId('report-direct'),
      token: Symbol('report-direct') as ToolExecutionToken,
      name: 'case_report',
      arguments: report,
      deferContext() {},
      concludeTurn() {},
    })).rejects.toThrow('owning agent session')
    await expect(tool.execute(report, {
      signal,
      callId: CallId('report-unbound-direct'),
      rootCallId: CallId('report-unbound-direct'),
      token: Symbol('report-unbound-direct') as ToolExecutionToken,
      name: 'case_report',
      arguments: report,
      agent: agent('unbound-direct'),
      deferContext() {},
      concludeTurn() {},
    })).rejects.toThrow('unbound: assign victim vs c2 on the cited conversation.')
    const blank = await ctx.tools.execute({
      signal,
      callId: CallId('report3'),
      name: 'case_report',
      arguments: { ...report, what: '   ' },
      agent: owner,
    })
    expect(blank.isError).toBe(true)
    expect(text(blank)).toContain('what must be a non-empty string')
  })

  it('presents calls and unregisters tools on fiber dispose (HMR-safety)', async () => {
    const { ctx, toolsFiber } = await setup()
    expect(ctx.tools.get('pcap_info')?.presentCall?.({ path: 'a.pcap' })?.title).toBe('pcap info')
    expect(ctx.tools.get('pcap_filter')?.presentCall?.({ path: 'a.pcap' })?.title).toBe('pcap filter')
    expect(ctx.tools.get('logs')?.presentCall?.({ path: 'a.log' })?.title).toBe('logs')
    expect(ctx.tools.get('case_report')?.presentCall?.({
      what: 'b', when: 'c', why: 'e', how: 'f',
    })?.title).toBe('Case report')
    expect(ctx.tools.get('bind_relationship')?.presentCall?.({
      src: '10.0.10.2', dst: '198.51.100.80', dport: 443, t: 't', evidence_id: 'e',
      endpoints: [{ addr: '10.0.10.2', role: 'victim', because: 'conversation' }],
    })?.title).toBe('Bind conversation')
    expect(ctx.tools.get('pcap_info')?.isConcurrencySafe?.({ path: 'a.pcap' })).toBe(true)
    expect(ctx.tools.get('pcap_filter')?.isConcurrencySafe?.({ path: 'a.pcap' })).toBe(true)
    expect(ctx.tools.get('logs')?.isConcurrencySafe?.({ path: 'a.log' })).toBe(true)
    expect(ctx.tools.get('pcap_info')?.output.render({}, { text: 'meta' })).toEqual([
      { type: 'text', text: 'meta' },
    ])
    expect(ctx.tools.get('pcap_filter')?.output.render({}, { text: 'rows' })).toEqual([
      { type: 'text', text: 'rows' },
    ])
    expect(ctx.tools.get('logs')?.output.render({}, { text: 'log' })).toEqual([
      { type: 'text', text: 'log' },
    ])
    const names = ctx.tools.schemas().map(schema => schema.name)
    expect(names).toEqual(expect.arrayContaining([
      'pcap_info', 'pcap_filter', 'logs', 'case_report', 'bind_relationship',
    ]))
    await toolsFiber.dispose()
    expect(ctx.tools.schemas().some(schema => schema.name === 'pcap_filter')).toBe(false)
  })

  it('surfaces helper ENOENT, timeout, cancel, and nonzero stdout', async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-helper-'))
    await expect(runHelper(join(root, 'missing'), [], {
      cwd: root, timeoutMs: 1000, maxOutputChars: 100, signal,
    })).rejects.toThrow('is not installed')
    const sleepy = await script(root, 'sleepy', 'sleep 5')
    await expect(runHelper(sleepy, [], {
      cwd: root, timeoutMs: 50, maxOutputChars: 100, signal,
    })).rejects.toThrow('exceeded commandTimeoutMs')
    const abort = new AbortController()
    abort.abort()
    const echo = await script(root, 'echoer', 'echo hi')
    await expect(runHelper(echo, [], {
      cwd: root, timeoutMs: 1000, maxOutputChars: 100, signal: abort.signal,
    })).rejects.toThrow('was cancelled')
    const fail = await script(root, 'failer', 'echo out; echo err >&2; exit 2')
    const mixed = await runHelper(fail, [], {
      cwd: root, timeoutMs: 1000, maxOutputChars: 100, signal,
    })
    expect(mixed).toContain('out')
    const explode = await script(root, 'explode', 'kill -s KILL $$')
    await expect(runHelper(explode, [], {
      cwd: root, timeoutMs: 1000, maxOutputChars: 100, signal,
    })).rejects.toThrow(/failed|exceeded/)
    const noisy = await script(root, 'noisy', 'echo out; echo err >&2')
    expect(await runHelper(noisy, [], {
      cwd: root, timeoutMs: 1000, maxOutputChars: 100, signal,
    })).toContain('err')
  })

  it('rejects a non-file pcap path and rethrows a non-ENOENT capinfos failure', async () => {
    const { ctx, owner, caseDir } = await setup()
    const result = await ctx.tools.execute({
      signal, callId: CallId('dir'), name: 'pcap_info', arguments: { path: caseDir }, agent: owner,
    })
    expect(result.isError).toBe(true)
    expect(text(result)).toContain('is not a file')
    const staging = await mkdtemp(join(tmpdir(), 'dsh-cap-fail-'))
    const explode = await script(staging, 'explode', 'kill -s KILL $$')
    const failed = await setup({ capinfosBin: explode })
    const info = await failed.ctx.tools.execute({
      signal, callId: CallId('boom'), name: 'pcap_info', arguments: { path: 'evidence/a.pcap' }, agent: failed.owner,
    })
    expect(info.isError).toBe(true)
    expect(text(info)).toMatch(/failed|exceeded|cancelled/)
    await failed.ctx.fiber.dispose()
    await rm(staging, { recursive: true, force: true })
  })
})
