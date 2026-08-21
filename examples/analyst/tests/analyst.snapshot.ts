/** Keyless assembled transcript for the analyst investigation preset. */

import { chmod, mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { LOADER_SMOKE_TEST_TIMEOUT_MS, runLoaderSmoke } from '@deepseek-ai/dsh-loader-smoke'
import { describe, expect, it } from 'vitest'

const scenarioDir = join(dirname(fileURLToPath(import.meta.url)), 'snapshots/pcap-case')
const configPath = fileURLToPath(new URL('../analyst.cordis.snapshot.yml', import.meta.url))
const binScript = fileURLToPath(new URL('../../headless-agent/tests/fixtures/headless-driver.ts', import.meta.url))
const tsconfigPath = fileURLToPath(new URL('../../../tsconfig.json', import.meta.url))

interface JsonObject {
  [key: string]: unknown
}

function parseJsonl(content: string): JsonObject[] {
  return content.split('\n')
    .filter(line => line.trim().length > 0)
    .map(line => JSON.parse(line) as JsonObject)
}

describe('analyst pcap-case snapshot', () => {
  it('harvests identities, issues hunts, and records a 5W1H close packet', async () => {
    const input = JSON.parse(await readFile(join(scenarioDir, 'input.json'), 'utf8')) as {
      steps?: { op?: unknown; text?: unknown }[]
    }
    const prompt = input.steps?.find(step => step.op === 'prompt')?.text
    if (typeof prompt !== 'string') throw new Error('pcap-case input has no prompt step')

    const env: NodeJS.ProcessEnv = {
      DSH_SNAPSHOT: 'replay',
      DSH_SNAPSHOT_OVERRIDE: join(scenarioDir, 'replay.override.json'),
      DSH_SNAPSHOT_FILE: join(scenarioDir, 'session.jsonl'),
      NODE_OPTIONS: [process.env.NODE_OPTIONS, '--disable-warning=ExperimentalWarning'].filter(Boolean).join(' '),
    }

    const result = await runLoaderSmoke({
      label: 'analyst pcap-case headless stream-json snapshot',
      tempDirPrefix: 'dsh-analyst-snapshot-',
      binScript,
      libBinScript: binScript,
      configPath,
      binArgs: [configPath, prompt],
      tsconfigPath,
      env,
      prepare: async (cwd) => {
        env.DSH_CASE_DIR = cwd
        env.DSH_TSHARK_BIN = join(cwd, 'tshark')
        env.DSH_CAPINFOS_BIN = join(cwd, 'capinfos')
        await mkdir(join(cwd, 'evidence'))
        await writeFile(join(cwd, 'evidence', 'a.pcap'), 'pcap')
        await writeFile(join(cwd, 'tshark'), [
          '#!/bin/sh',
          'printf "10.0.10.2 → 198.51.100.80 TCP\\nhostname: workstation-a\\n10.0.10.2\\nkerberos.CNameString: user-a\\n"',
          '',
        ].join('\n'))
        await writeFile(join(cwd, 'capinfos'), '#!/bin/sh\necho capinfos-ok\n')
        await chmod(join(cwd, 'tshark'), 0o755)
        await chmod(join(cwd, 'capinfos'), 0o755)
      },
      inspect: async (cwd) => {
        const files = (await readdir(join(cwd, '.sessions'), { recursive: true }))
          .filter(file => file.endsWith('.jsonl'))
        expect(files).toHaveLength(1)
        const records = parseJsonl(await readFile(join(cwd, '.sessions', files[0]!), 'utf8'))
        const calls = records.filter(record => record.type === 'tool/call')
          .map(record => (record.data as JsonObject | undefined)?.name)
        expect(calls).toEqual(['pcap_filter', 'bind_relationship', 'case_report'])
        expect(records.some(record => record.type === 'investigation/identity')).toBe(true)
        expect(records.some(record => record.type === 'investigation/hunt')).toBe(true)
        expect(records.some(record => record.type === 'investigation/bind')).toBe(true)
        const report = records.find(record => record.type === 'investigation/report')
        const who = (report?.data as JsonObject | undefined)?.who as JsonObject | undefined
        expect(who?.entity_id).toBe('10.0.10.2')
        expect(who?.ip).toBe('10.0.10.2')
        expect((report?.data as JsonObject | undefined)?.how).toContain('SAMR')
        const identities = records.filter(record => record.type === 'investigation/identity')
          .map(record => (record.data as JsonObject).kind)
        expect(identities).toEqual(expect.arrayContaining(['hostname', 'ip', 'user']))
        const hunts = records.filter(record => record.type === 'investigation/hunt')
          .map(record => (record.data as JsonObject).kind)
        expect(hunts).toEqual(expect.arrayContaining(['kerberos-cname', 'samr-userinfo']))
      },
    })

    expect(result.stderr).toBe('')
    expect(result.stdout).toContain('CASE CLOSED')
  }, LOADER_SMOKE_TEST_TIMEOUT_MS)
})
