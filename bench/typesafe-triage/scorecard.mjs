// One scorecard per investigation: the qualities a buyer asks about, measured
// from the session log the harness already writes.
//
//   node bench/typesafe-triage/scorecard.mjs <run-dir> [--case=YYYY-MM-DD]
//
// Metrics split in two, and the split is the point:
//
//   production  needs no answer key, so it runs on a customer's own captures.
//               Groundedness is the flagship — every address the report asserts
//               must exist in the packets. That catches confabulation, which is
//               the failure that destroys analyst trust, without ground truth.
//
//   bench       needs the published notes, so it only runs on this corpus. It
//               calibrates the production metrics; it cannot ship.
//
// Records append to runs/scorecard.jsonl. Never overwrite: a trend needs history.
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import zlib from 'node:zlib'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { observe } from './observe.mjs'
import { iocMatch, readTruth } from './truth.mjs'

/**
 * Token rates in USD per million. OPERATOR-SUPPLIED: these are list prices and
 * are not verified against any contract. Override with DSH_RATE_CACHE_READ /
 * _INPUT / _OUTPUT. Cost is reported alongside raw token counts so a wrong rate
 * card never hides the measurement underneath it.
 */
const RATES = {
  cacheRead: Number(process.env.DSH_RATE_CACHE_READ ?? 0.028),
  input: Number(process.env.DSH_RATE_INPUT ?? 0.28),
  output: Number(process.env.DSH_RATE_OUTPUT ?? 0.42),
}

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
const DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi
/**
 * Public suffixes a report's network indicators actually use.
 *
 * An allowlist, not a denylist of file extensions: the first version flagged
 * `keychain-2.db`, `notestore.sqlite` and the username `glen.powers` as
 * fabricated addresses, which measured the regex rather than the report.
 * Groundedness is about network indicators, so only tokens whose last label is
 * a real public suffix are checked at all.
 */
const PUBLIC_SUFFIXES = new Set([
  'com', 'net', 'org', 'io', 'online', 'us', 'top', 'xyz', 'ru', 'cn', 'info',
  'biz', 'co', 'dev', 'app', 'site', 'shop', 'live', 'club', 'space', 'icu',
  'cc', 'me', 'tv', 'uk', 'de', 'fr', 'nl', 'pro', 'store', 'work', 'link',
  'fun', 'life', 'world', 'digital', 'cloud', 'tech', 'host', 'website',
  'agency', 'solutions', 'tools', 'global', 'network', 'systems', 'gov', 'edu',
])

/** Decode a multi-frame zstd session log; each append is its own frame. */
function decode(buf) {
  const out = []
  let off = 0
  while (off < buf.length) {
    let frame
    try { frame = zlib.zstdDecompressSync(buf.subarray(off)) } catch { break }
    out.push(frame.toString())
    let next = -1
    for (let i = off + 4; i + 4 <= buf.length; i++) {
      if (buf[i] === 0x28 && buf[i + 1] === 0xB5 && buf[i + 2] === 0x2F && buf[i + 3] === 0xFD) {
        try { zlib.zstdDecompressSync(buf.subarray(i)); next = i; break } catch { /* mid-frame */ }
      }
    }
    if (next < 0) break
    off = next
  }
  return out.join('')
}

/** The largest session log written for `caseDir`. Side sessions are touched later. */
async function sessionLog(caseDir) {
  const home = path.join(os.homedir(), '.dsh/sessions')
  const want = path.basename(path.resolve(caseDir))
  const dir = (await fs.readdir(home)).find((d) => d.endsWith(`${want}--`))
  if (dir === undefined) throw new Error(`no session log for ${caseDir}`)
  const root = path.join(home, dir)
  let best
  for (const s of await fs.readdir(root)) {
    const file = path.join(root, s, 'session.jsonl.zstd')
    const stat = await fs.stat(file).catch(() => undefined)
    if (stat !== undefined && (best === undefined || stat.size > best.size)) best = { file, size: stat.size }
  }
  if (best === undefined) throw new Error(`no session.jsonl.zstd under ${root}`)
  return best.file
}

/** Walk the log once; everything below reads from this. */
function fold(jsonl) {
  const s = {
    t0: undefined, tLast: undefined, tFirstBind: undefined, tReport: undefined,
    llmCalls: 0, tokens: { input: 0, output: 0, cacheRead: 0, reasoning: 0 },
    toolCalls: 0, byTool: {}, refusals: 0, searches: 0, searchQueries: [],
    submittedReport: undefined, lastReport: undefined, bind: undefined,
    binds: [], models: new Set(), softenedRule: false, hardRule: false,
  }
  const pend = new Map()
  for (const line of jsonl.split('\n')) {
    if (line === '') continue
    let e
    try { e = JSON.parse(line) } catch { continue }
    const d = e.data ?? {}
    if (e.type === 'session') s.t0 = e.createdAt
    if (typeof e.time === 'number') s.tLast = Math.max(s.tLast ?? 0, e.time)
    const usage = e.usage ?? d.usage
    if (usage !== undefined) {
      s.llmCalls += 1
      s.tokens.input += usage.inputTokens ?? 0
      s.tokens.output += usage.outputTokens ?? 0
      s.tokens.cacheRead += usage.cacheReadTokens ?? 0
      s.tokens.reasoning += usage.reasoningTokens ?? 0
    }
    if (e.type === 'tool/call') {
      s.toolCalls += 1
      s.byTool[d.name] = (s.byTool[d.name] ?? 0) + 1
      pend.set(d.callId, d.name)
      if (d.name === 'web_search') {
        s.searches += 1
        try { s.searchQueries.push(...JSON.parse(d.arguments).queries ?? []) } catch { /* chunked */ }
      }
      if (d.name === 'case_report') {
        try { s.submittedReport = JSON.parse(d.arguments) } catch { /* chunked */ }
      }
      if (d.name === 'bind_relationship') {
        try { s.binds.push(JSON.parse(d.arguments)) } catch { /* chunked */ }
      }
    }
    if (e.type === 'tool/result') {
      const name = pend.get(d.message?.source?.callId)
      if (name !== undefined && /unbound:|"ok\\?": ?false/.test(JSON.stringify(d))) s.refusals += 1
    }
    if (e.type === 'investigation/bind') { s.bind = d; s.tFirstBind ??= e.time }
    if (e.type === 'investigation/report') { s.lastReport = d; s.tReport ??= e.time }
    if (typeof line === 'string') {
      if (!s.softenedRule && line.includes('propose the bind and cite the hostname')) s.softenedRule = true
      if (!s.hardRule && line.includes('cannot be a LAN address or a well-known CDN')) s.hardRule = true
    }
    const served = d.model ?? e.model
    if (typeof served === 'string' && served !== '') s.models.add(served)
  }
  return s
}

/**
 * Every address and name the report asserts as a network indicator.
 *
 * Filesystem paths are stripped first. `C:\\Windows\\Microsoft.NET\\Framework`
 * otherwise yields `microsoft.net`, and a CIDR such as `185.14.92.0/24` yields
 * its network base — both are correct reporting, and scoring them as
 * fabrications would make the metric untrustworthy in the one direction that
 * matters.
 * @param report - the persisted case report.
 * @returns asserted IPv4s and DNS names.
 */
function assertedAtoms(report) {
  const blob = JSON.stringify(report ?? {})
    // Windows and UNC paths, up to the next quote or whitespace.
    .replaceAll(/[A-Za-z]:\\\\[^\s"]*/g, ' ')
    .replaceAll(/\\\\{2}[^\s"]*/g, ' ')
    // CIDR notation: the prefix is a range claim, not a host claim.
    .replaceAll(/\b\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}\b/g, ' ')
  const ips = new Set(blob.match(IPV4) ?? [])
  const names = new Set((blob.match(DOMAIN) ?? [])
    .map((n) => n.toLowerCase())
    .filter((n) => PUBLIC_SUFFIXES.has(n.slice(n.lastIndexOf('.') + 1))))
  return { ips, names }
}

const run = promisify(execFile)

/**
 * Every address and DNS name the packets actually carry.
 *
 * Grounding must come from the capture itself, not from `observe`'s filtered
 * destination list: that list drops LAN infrastructure, so the gateway the
 * report legitimately names would score as a fabrication.
 * @param pcaps - capture paths.
 * @returns sets of IPv4s and lowercased DNS names present in the traffic.
 */
async function captureAtoms(pcaps) {
  const ips = new Set()
  const names = new Set()
  for (const pcap of pcaps) {
    const addrs = await run('tshark', ['-r', pcap, '-q', '-z', 'endpoints,ip'], { maxBuffer: 1 << 28 })
    for (const m of addrs.stdout.matchAll(IPV4)) ips.add(m[0])
    // Resolved-but-never-contacted answers count as grounded: a Cloudflare name
    // returns several A records and the host uses one. Naming the others is
    // reporting what the packets carried, not inventing an address.
    const answers = await run('tshark', [
      '-r', pcap, '-T', 'fields', '-e', 'dns.a',
    ], { maxBuffer: 1 << 28 })
    for (const m of answers.stdout.matchAll(IPV4)) ips.add(m[0])
    const dns = await run('tshark', [
      '-r', pcap, '-T', 'fields',
      '-e', 'dns.qry.name', '-e', 'dns.resp.name', '-e', 'tls.handshake.extensions_server_name',
      '-e', 'http.host', '-e', 'nbns.name',
    ], { maxBuffer: 1 << 28 })
    for (const token of dns.stdout.split(/[\s,]+/)) {
      const name = token.trim().toLowerCase().replace(/\.+$/, '')
      if (name !== '' && name.includes('.')) names.add(name)
    }
  }
  return { ips, names }
}

const round = (n, p = 2) => Math.round(n * 10 ** p) / 10 ** p

const runDir = process.argv[2]
if (runDir === undefined) throw new Error('usage: scorecard.mjs <run-dir> [--case=YYYY-MM-DD]')
const caseId = process.argv.find((a) => a.startsWith('--case='))?.slice(7)
  ?? path.basename(runDir).match(/\d{4}-\d{2}-\d{2}/)?.[0]

const s = fold(decode(await fs.readFile(await sessionLog(runDir))))
const pcaps = (await fs.readdir(runDir))
  .filter((f) => f.endsWith('.pcap') || f.endsWith('.pcapng'))
  .map((f) => path.join(runDir, f))
const dests = await observe(pcaps)

// Groundedness: what the capture can support, with no answer key.
const { ips: capIps, names: capNames } = await captureAtoms(pcaps)
const asserted = assertedAtoms(s.lastReport)
const ungroundedIps = [...asserted.ips].filter((ip) => !capIps.has(ip))
const ungroundedNames = [...asserted.names]
  .filter((n) => !capNames.has(n) && ![...capNames].some((c) => c.endsWith(n) || n.endsWith(c)))
const groundedTotal = asserted.ips.size + asserted.names.size
const ungrounded = ungroundedIps.length + ungroundedNames.length

// Degradation: fields the model submitted that the persisted report no longer has.
// `who` may be submitted as a bare handle string rather than an object; keying
// a string yields its character indices, which is what produced a `lost` list
// of 0..73 on one run.
const asSlot = (v) => (typeof v === 'object' && v !== null ? v : {})
const subWho = asSlot(s.submittedReport?.who)
const lastWho = asSlot(s.lastReport?.who)
const lostFields = Object.keys(subWho)
  .filter((k) => typeof subWho[k] === 'string' && lastWho[k] === undefined)

const endpoints = s.bind?.endpoints ?? []
const cited = endpoints.filter((e) => typeof e.because === 'string' && e.because.trim() !== '')
const cost = round(
  (s.tokens.cacheRead * RATES.cacheRead + s.tokens.input * RATES.input
    + s.tokens.output * RATES.output) / 1e6, 4)

const record = {
  run: path.basename(runDir), case: caseId, at: new Date().toISOString(),
  config: {
    models: [...s.models], ruleSoftened: s.softenedRule && !s.hardRule,
    ruleContradiction: s.softenedRule && s.hardRule,
    // The capture filenames are part of the input, not decoration: MTA names
    // captures after the malware family, so a run given the original name is
    // told the answer. Two runs that differ only here are not a variance pair.
    captures: pcaps.map((f) => path.basename(f)),
    captureNamesNeutral: pcaps.every((f) => /^capture-/.test(path.basename(f))),
  },
  production: {
    closed: s.lastReport !== undefined,
    timeToFirstBindSec: s.tFirstBind === undefined ? undefined : round((s.tFirstBind - s.t0) / 1000, 1),
    timeToReportSec: s.tReport === undefined ? undefined : round((s.tReport - s.t0) / 1000, 1),
    wallSec: round((s.tLast - s.t0) / 1000, 1),
    llmCalls: s.llmCalls, toolCalls: s.toolCalls, refusals: s.refusals,
    tokens: s.tokens, costUsd: cost,
    groundedPct: groundedTotal === 0 ? undefined : Math.round((100 * (groundedTotal - ungrounded)) / groundedTotal),
    ungrounded: [...ungroundedIps, ...ungroundedNames].slice(0, 8),
    citedEndpointsPct: endpoints.length === 0 ? undefined : Math.round((100 * cited.length) / endpoints.length),
    verifierConsultations: s.binds.length,
    externalSearches: s.searches,
    harnessLostFields: lostFields,
  },
  bench: undefined,
}

if (caseId !== undefined) {
  const caseDir = path.join(import.meta.dirname, 'cases', caseId)
  const notes = (await fs.readdir(caseDir).catch(() => [])).find((f) => f.endsWith('.txt'))
  if (notes !== undefined) {
    const truth = await readTruth(path.join(caseDir, notes))
    const c2 = endpoints.find((e) => e.role === 'c2')?.addr
    const reached = new Set()
    for (const dest of dests) {
      const ioc = iocMatch(truth, dest)
      if (ioc !== undefined) reached.add(ioc)
    }
    const blob = JSON.stringify(s.lastReport ?? {}).toLowerCase()
    const hit = [...reached].filter((i) => blob.includes(i.toLowerCase()))
    record.bench = {
      c2Correct: c2 !== undefined && truth.ips.has(c2), boundC2: c2,
      victimBound: endpoints.some((e) => e.role === 'victim'),
      iocCoveragePct: reached.size === 0 ? undefined : Math.round((100 * hit.length) / reached.size),
      iocMissed: [...reached].filter((i) => !hit.includes(i)),
    }
  }
}

const ledger = path.join(import.meta.dirname, 'runs/scorecard.jsonl')
await fs.appendFile(ledger, `${JSON.stringify(record)}\n`)
console.log(JSON.stringify(record, undefined, 1))
