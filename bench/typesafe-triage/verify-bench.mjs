// Grade the bind verifier against the gate the plugin ships.
//
// Every (LAN host, WAN destination) pair in the corpus is turned into a bind
// proposal. The post's IOC list says whether that bind is the right one. Two
// gates then decide whether to accept it:
//
//   shipped   `ipIsCdnOrUpdate` -- anycast prefix, then CDN suffix list
//   verifier  `c2_is_benign_service >= GATE`
//
// Both see the identical proposal. A correct accept is an IOC bind that passes;
// a correct reject is a benign destination that is stopped.
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  isCdnOrUpdateName, isCloudflareIpv4, isFastlyIpv4, isLanIpv4,
} from './baseline.mjs'
import { ensureCorpus } from './fetch.mjs'
import { observe } from './observe.mjs'
import { iocMatch, readTruth } from './truth.mjs'
import { GATE, exactDenial, gate, questionsFor, verifyState } from './verify.mjs'

const API = 'https://api.typesafe.ai/v1/systemone'
const MODEL = process.env.TYPESAFE_MODEL ?? 'jev-latest'
const CONCURRENCY = Number(process.env.BENCH_CONCURRENCY ?? 4)
const CACHE = path.join(import.meta.dirname, '.observations.json')

const KEY = (process.env.TYPESAFE_API_KEY ??
  await fs.readFile(path.join(os.homedir(), '.config/typesafe/api_key'), 'utf8')).trim()

/**
 * The gate the plugin ships, as `bind.ts` composes it: the anycast prefix test
 * runs FIRST, and only then are evidenced hostnames consulted. That order is
 * the whole finding, so it is reproduced exactly rather than paraphrased.
 */
function shippedRejects(c2) {
  if (isCloudflareIpv4(c2.ip) || isFastlyIpv4(c2.ip)) return 'anycast prefix'
  if (c2.names.some(isCdnOrUpdateName)) return 'CDN/update name'
  return undefined
}

async function ask(state, questions) {
  for (let attempt = 0; ; attempt++) {
    const r = await fetch(API, {
      method: 'POST',
      headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: MODEL, state, questions }),
    })
    if (r.ok) return await r.json()
    if ((r.status === 429 || r.status === 529) && attempt < 4) {
      await new Promise((res) => setTimeout(res, 500 * 2 ** attempt))
      continue
    }
    throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 160)}`)
  }
}

async function pool(items, limit, work) {
  const out = new Array(items.length)
  let next = 0
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++
      out[i] = await work(items[i])
    }
  }))
  return out
}

/** tshark is the slow part; observations do not change between runs. */
async function observations(cases) {
  let cache = {}
  try {
    cache = JSON.parse(await fs.readFile(CACHE, 'utf8'))
  } catch { /* first run */ }
  let dirty = false
  for (const c of cases) {
    if (cache[c.date] === undefined) {
      process.stdout.write(`  ${c.date}  reading capture...`)
      cache[c.date] = await observe(c.pcaps)
      console.log(` ${cache[c.date].length} destinations`)
      dirty = true
    }
  }
  if (dirty) await fs.writeFile(CACHE, JSON.stringify(cache))
  return cache
}

const pct = (x) => `${(x * 100).toFixed(0)}%`

async function main() {
  console.log('\n  fetching corpus...')
  const cases = await ensureCorpus({ log: () => {} })
  const obs = await observations(cases)

  const proposals = []
  for (const c of cases) {
    const truth = await readTruth(c.notes)
    const dests = obs[c.date]
    // The victim is the LAN host that did the talking, by frame share.
    const counts = new Map()
    for (const d of dests) {
      for (const h of d.lanHosts) counts.set(h, (counts.get(h) ?? 0) + 1)
    }
    const victimIp = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0]
    if (victimIp === undefined || !isLanIpv4(victimIp)) continue
    const victim = { ip: victimIp, names: [], state: { role: 'the host under investigation' } }

    for (const d of dests) {
      if (isLanIpv4(d.ip)) continue
      const ioc = iocMatch(truth, d)
      proposals.push({
        case: c.date, victim, c2: d,
        shouldAccept: ioc !== undefined, ioc,
      })
    }
  }

  console.log(`\n  ${proposals.length} bind proposals` +
    `  (${proposals.filter((p) => p.shouldAccept).length} the notes back)\n`)

  let calls = 0, inTok = 0
  const rows = await pool(proposals, CONCURRENCY, async (p) => {
    const exact = exactDenial({ victim: p.victim, c2: p.c2 })
    if (exact !== undefined) return { ...p, exact, verifier: undefined }
    const r = await ask(verifyState({ victim: p.victim, c2: p.c2 }), questionsFor())
    calls++
    inTok += r.usage?.input_tokens ?? 0
    return { ...p, exact: undefined, verifier: gate(r.answers) }
  })

  const graded = rows.filter((r) => r.verifier !== undefined)
  const score = (reject) => {
    let ok = 0, wrongAccept = 0, wrongReject = 0
    for (const r of graded) {
      const rejected = reject(r)
      if (rejected && r.shouldAccept) wrongReject++
      else if (!rejected && !r.shouldAccept) wrongAccept++
      else ok++
    }
    return { ok, wrongAccept, wrongReject, acc: ok / graded.length }
  }

  const shipped = score((r) => shippedRejects(r.c2) !== undefined)
  const verifier = score((r) => r.verifier.flag)

  // The docs are explicit that the gate belongs on your own data, not on a
  // borrowed constant. 0.7 is the cookbook's number for a different task.
  console.log(`  gate sweep -- where a red flag should stop a bind\n`)
  console.log(`    gate    correct   wrongly rejected   wrongly accepted`)
  for (const g of [0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.7]) {
    const s = score((r) => r.verifier.score >= g)
    console.log(`    ${g.toFixed(2)}${pct(s.acc).padStart(10)}` +
      `${String(s.wrongReject).padStart(19)}${String(s.wrongAccept).padStart(19)}`)
  }
  console.log()

  console.log(`  gate                        correct   wrongly rejected   wrongly accepted`)
  const line = (n, s) => console.log(`  ${n.padEnd(26)}${pct(s.acc).padStart(7)}` +
    `${String(s.wrongReject).padStart(19)}${String(s.wrongAccept).padStart(19)}`)
  line('shipped ipIsCdnOrUpdate', shipped)
  line(`verifier >= ${GATE}`, verifier)

  const lost = graded.filter((r) => r.shouldAccept && shippedRejects(r.c2) !== undefined)
  console.log(`\n  binds the shipped gate refuses although the notes name them C2\n`)
  for (const r of lost) {
    const v = r.verifier
    console.log(`    ${r.case}  ${r.c2.ip.padEnd(16)}${(r.c2.names[0] ?? '-').slice(0, 30).padEnd(32)}` +
      `shipped: refused (${shippedRejects(r.c2)})   verifier: ` +
      `${v.flag ? `refused (${v.worst} ${v.score.toFixed(2)})` : `allowed (worst ${v.score.toFixed(2)})`}`)
  }
  const rescued = lost.filter((r) => !r.verifier.flag).length
  console.log(`\n    ${rescued} of ${lost.length} rescued by the verifier`)

  const falseAccepts = graded.filter((r) => !r.shouldAccept && !r.verifier.flag)
  console.log(`\n  benign destinations the verifier would let bind as C2: ${falseAccepts.length}`)
  for (const r of falseAccepts.slice(0, 12)) {
    console.log(`    ${r.case}  ${r.c2.ip.padEnd(16)}${(r.c2.names[0] ?? '-').slice(0, 30).padEnd(32)}` +
      `worst ${r.verifier.worst} ${r.verifier.score.toFixed(2)}`)
  }

  console.log(`\n  ${calls} verifier calls, ${inTok} input tokens, ` +
    `$${(inTok / 1e6 * 0.042).toFixed(4)}`)
  console.log(`  ${rows.length - graded.length} proposals settled by exact checks, no model call\n`)

  await fs.writeFile(path.join(import.meta.dirname, 'verify-results.json'),
    `${JSON.stringify({ gate: GATE, shipped, verifier, rows }, undefined, 2)}\n`)
}

await main()
