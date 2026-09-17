// Grade one finished investigation against the notes the post published.
//
// The bench grades per-destination classification; this grades the thing the
// harness actually produces — a bound relationship and a 5W1H report. They are
// different questions, and conflating them overstates what a classification
// error costs. A missed Cloudflare destination does not block the case here; it
// costs IOC coverage in the report, which is what `iocCoverage` measures.
//
//   node bench/typesafe-triage/grade.mjs <run-dir> [--case=YYYY-MM-DD]
//
// The run directory is the case directory the investigation ran in; its session
// log is found by matching the harness session-home slug.
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import zlib from 'node:zlib'
import { observe } from './observe.mjs'
import { iocMatch, readTruth } from './truth.mjs'

/** Decode a multi-frame zstd session log. Each append is its own frame. */
function decodeSessionLog(buf) {
  const out = []
  let off = 0
  while (off < buf.length) {
    let frame
    try { frame = zlib.zstdDecompressSync(buf.subarray(off)) } catch { break }
    out.push(frame.toString())
    let next = -1
    for (let i = off + 4; i + 4 <= buf.length; i++) {
      if (buf[i] === 0x28 && buf[i + 1] === 0xB5 && buf[i + 2] === 0x2F && buf[i + 3] === 0xFD) {
        try { zlib.zstdDecompressSync(buf.subarray(i)); next = i; break } catch { /* not a frame start */ }
      }
    }
    if (next < 0) break
    off = next
  }
  return out.join('')
}

/** The newest session log written for `caseDir`, by log size. */
async function findSessionLog(caseDir) {
  const home = path.join(os.homedir(), '.dsh/sessions')
  const slug = `--${path.resolve(caseDir).replaceAll('/', '-').replace(/^-/, '')}--`
  const dirs = await fs.readdir(home)
  const match = dirs.find((d) => d === slug) ?? dirs.find((d) => d.endsWith(`${path.basename(caseDir)}--`))
  if (match === undefined) throw new Error(`no session log for ${caseDir}`)
  const root = path.join(home, match)
  const sessions = await fs.readdir(root)
  let best
  for (const s of sessions) {
    const file = path.join(root, s, 'session.jsonl.zstd')
    const stat = await fs.stat(file).catch(() => undefined)
    // Largest log, not newest: side sessions (title generation) are touched later.
    if (stat && (best === undefined || stat.size > best.size)) best = { file, size: stat.size }
  }
  if (best === undefined) throw new Error(`no session.jsonl.zstd under ${root}`)
  return best.file
}

/** Last bind and report events on the log. */
function readOutcome(jsonl) {
  let bind, report
  for (const line of jsonl.split('\n')) {
    if (line === '') continue
    let e
    try { e = JSON.parse(line) } catch { continue }
    if (e.type === 'investigation/bind') bind = e.data
    if (e.type === 'investigation/report') report = e.data
  }
  return { bind, report }
}

const norm = (v) => typeof v === 'string' ? v.toLowerCase().replace(/\.+$/, '') : undefined

/**
 * Every IOC the report names, over every IOC the capture actually reached.
 *
 * The denominator is NOT the whole notes file. A post lists sandbox links, mail
 * relays from `Received:` headers, and hashes the traffic never carried; an
 * investigation cannot name what its packets never saw. Scoping to contacted
 * destinations is what makes this a measure of the report rather than of the
 * notes parser.
 */
function iocCoverage(truth, report, dests) {
  const blob = JSON.stringify(report ?? {}).toLowerCase()
  const reached = new Set()
  for (const dest of dests) {
    const ioc = iocMatch(truth, dest)
    if (ioc !== undefined) reached.add(ioc)
  }
  const all = [...reached]
  const hit = all.filter((ioc) => blob.includes(ioc.toLowerCase()))
  return { hit, all, pct: all.length === 0 ? 0 : Math.round((100 * hit.length) / all.length) }
}

const runDir = process.argv[2]
if (runDir === undefined) throw new Error('usage: grade.mjs <run-dir> [--case=YYYY-MM-DD]')
const caseArg = process.argv.find((a) => a.startsWith('--case='))?.slice(7)
const caseId = caseArg ?? path.basename(runDir).match(/\d{4}-\d{2}-\d{2}/)?.[0]
if (caseId === undefined) throw new Error('pass --case=YYYY-MM-DD; the run dir does not name one')

const caseDir = path.join(import.meta.dirname, 'cases', caseId)
const notes = (await fs.readdir(caseDir)).find((f) => f.endsWith('.txt'))
const truth = await readTruth(path.join(caseDir, notes))

const jsonl = decodeSessionLog(await fs.readFile(await findSessionLog(runDir)))
const { bind, report } = readOutcome(jsonl)

const c2 = bind?.endpoints?.find((e) => e.role === 'c2')?.addr
const victim = bind?.endpoints?.find((e) => e.role === 'victim')?.addr
const who = report?.who ?? {}

// A bound C2 counts when the post listed that address, or a name the capture
// resolved for it. A victim IP is never an IOC — it is graded as "did the bind
// name exactly one LAN host", which the engine already enforces.
const c2Ok = c2 !== undefined && truth.ips.has(c2)
// A slot is only right when it is present, is not itself a published IOC (the
// harvester has projected a resolved domain as the victim's own name), and
// carries identifier structure — an earlier run persisted `only` and `==`,
// which a presence check alone scores as a pass.
const JUNK = new RegExp('^(?:only|the|host|hostname|name|client|server|source|destination|unknown'
  + '|all|none|true|false|null|browser|nbns|llmnr|mdns|dns|smb2?|kerberos|samr|ldap|https?|tls'
  + '|ssl|tcp|udp|ipv?[46]?|eth|arp|dhcp|icmp|ntp|quic|data)$', 'i')
const plausible = (v) => typeof v === 'string' && /[a-z0-9]/i.test(v) && !JUNK.test(v.trim())
const hostnameOk = plausible(who.hostname) && !truth.hosts.has(norm(who.hostname))
const userOk = plausible(who.user)
const pcaps = (await fs.readdir(runDir))
  .filter((f) => f.endsWith('.pcap') || f.endsWith('.pcapng'))
  .map((f) => path.join(runDir, f))
const cov = iocCoverage(truth, report, await observe(pcaps))

const mark = (ok) => ok ? '✓' : '✗'
console.log(`\ncase ${caseId}   run ${path.basename(runDir)}`)
console.log(`  bound C2        ${mark(c2Ok)}  ${c2 ?? '(none)'}${c2Ok ? '' : '   not in the published IOC list'}`)
console.log(`  bound victim    ${mark(victim !== undefined)}  ${victim ?? '(none)'}`)
console.log(`  who.hostname    ${mark(hostnameOk)}  ${who.hostname ?? '(omitted)'}${hostnameOk ? '' : '   <- not a plausible victim hostname'}`)
console.log(`  who.user        ${mark(userOk)}  ${who.user ?? '(omitted)'}${userOk ? '' : '   not a plausible identifier'}`)
console.log(`  IOC coverage    ${String(cov.pct).padStart(3)}%  ${cov.hit.length}/${cov.all.length} IOCs the capture reached, named in the report`)
const missed = cov.all.filter((i) => !cov.hit.includes(i))
if (missed.length > 0) console.log(`  missed          ${missed.slice(0, 8).join(', ')}${missed.length > 8 ? ` (+${missed.length - 8})` : ''}`)
console.log()
