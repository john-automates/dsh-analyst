// Grade a System One model against the analyst plugin's shipped heuristic on
// real malware-traffic-analysis.net captures.
//
//   attacker_infra     Noul   -- attacker-owned server or domain
//   malware_used_it    Noul   -- malware drove the traffic, legitimate host or not
//   benign_background  Noul   -- CDN / update / telemetry / OCSP background
//   label              Choice -- c2 / abused_service / cdn / update / distractor
//
// All four are asked over the same state in ONE request: they are independent,
// so they run in parallel and cannot see one another's answers. The policy that
// turns them into a call lives in `suspicion()` below, in code, so changing a
// threshold or a weight needs no new inference.
//
// The comparison is honest the way agar's is: the hand-coded pilot sees the
// IDENTICAL observation. Any difference is judgment, not evidence.
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { baselineCall } from './baseline.mjs'
import { ensureCorpus } from './fetch.mjs'
import { observe } from './observe.mjs'
import { iocMatch, readTruth } from './truth.mjs'

const API = 'https://api.typesafe.ai/v1/systemone'
// Requested alias; `servedModels` below records what actually answered.
const MODEL = process.env.TYPESAFE_MODEL ?? 'jev-1.13.0'
const servedModels = new Set()
const CONCURRENCY = Number(process.env.BENCH_CONCURRENCY ?? 4)
const THRESHOLD = Number(process.env.BENCH_THRESHOLD ?? 0.5)
// jev input-token price used by the agar demo in seadragon.
const PER_MTOK = 0.042

const KEY = (process.env.TYPESAFE_API_KEY ??
  await fs.readFile(path.join(os.homedir(), '.config/typesafe/api_key'), 'utf8')).trim()

const QUESTIONS = {
  // Two Nouls, not one, because the notes' IOC list is the union of two
  // different things and the first run proved they cannot share a question.
  // Asking "is this malicious?" got 0.07 for accounts.google.com and 0.08 for
  // ip-api.com -- both correct answers to that question, and both listed by the
  // post, because the malware used them. Code takes the union.
  attacker_infra: {
    type: 'noul',
    instructions:
      'This destination is infrastructure the attacker controls: a malware ' +
      'command-and-control server, an exfiltration endpoint, or a server or ' +
      'domain set up to deliver a malicious payload or script.',
  },
  malware_used_it: {
    type: 'noul',
    instructions:
      'Malware running on the host that contacted this destination is what drove ' +
      'this traffic, rather than the user browsing or the operating system going ' +
      'about its business. This is true even when the destination itself is a ' +
      'legitimate, widely used service -- malware routinely calls IP-geolocation ' +
      'lookups, messaging-bot APIs, paste and file-sharing sites, and ' +
      'public-IP-echo services to fingerprint the host or move data.',
  },
  benign_background: {
    type: 'noul',
    instructions:
      'This is ordinary background traffic of no interest to an incident ' +
      'responder: a content delivery network, an operating-system or browser ' +
      'update or telemetry endpoint, an ad or analytics beacon, a font or asset ' +
      'host, or a certificate revocation check.',
  },
  label: {
    type: 'choice',
    instructions:
      'A host on a local network contacted this destination during a packet ' +
      'capture. What kind of destination is it?',
    criteria: {
      c2: 'Attacker-controlled: malware command-and-control, data exfiltration, ' +
        'or the server that delivered the malicious payload or script.',
      abused_service: 'A legitimate public service that the malware itself called -- ' +
        'IP-geolocation or public-IP echo, a messaging-bot API, a paste or ' +
        'file-sharing host used to stage or exfiltrate data.',
      cdn: 'A content delivery network, font or asset host, or edge cache serving ' +
        'ordinary web assets.',
      update: 'An operating-system, browser, or application update or telemetry service.',
      distractor: 'Ordinary benign traffic that is none of the above -- a normal ' +
        'public web service the user browsed, an ad or analytics host, or ' +
        'certificate revocation checking.',
    },
  },
}

/**
 * The composition, kept out of the model: a post lists a destination when it is
 * attacker infrastructure OR when the malware called it. Policy lives here so a
 * threshold change does not need another inference pass.
 */
export function suspicion(a) {
  return Math.max(a.attacker_infra.noul, a.malware_used_it.noul) *
    (1 - a.benign_background.noul)
}

async function ask(state) {
  const t0 = Date.now()
  for (let attempt = 0; ; attempt++) {
    const r = await fetch(API, {
      method: 'POST',
      headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: MODEL, state, questions: QUESTIONS }),
    })
    if (r.ok) {
      const j = await r.json()
      // `served` is the version that actually answered, not the alias we asked
      // for. Recording only the alias made earlier runs unreproducible: an F1
      // is a claim about a model, and `jev-latest` does not name one.
      if (typeof j.model === 'string') servedModels.add(j.model)
      return { answers: j.answers, usage: j.usage, served: j.model, latency: Date.now() - t0 }
    }
    // 429 / 529 are the documented retryable pair.
    if ((r.status === 429 || r.status === 529) && attempt < 4) {
      await new Promise((res) => setTimeout(res, 500 * 2 ** attempt))
      continue
    }
    throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`)
  }
}

/** Run `work` over `items` with a fixed number in flight. */
async function pool(items, limit, work) {
  const out = new Array(items.length)
  let next = 0
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++
      out[i] = await work(items[i], i)
    }
  }))
  return out
}

function rates(rows, call) {
  let tp = 0, fp = 0, fn = 0, tn = 0
  for (const r of rows) {
    const p = call(r), t = r.truth
    if (p && t) tp++
    else if (p && !t) fp++
    else if (!p && t) fn++
    else tn++
  }
  const prec = tp + fp === 0 ? 0 : tp / (tp + fp)
  const rec = tp + fn === 0 ? 0 : tp / (tp + fn)
  const f1 = prec + rec === 0 ? 0 : 2 * prec * rec / (prec + rec)
  return { tp, fp, fn, tn, prec, rec, f1 }
}

const pct = (x) => `${(x * 100).toFixed(0)}%`

async function main() {
  const only = process.argv.find((a) => a.startsWith('--case='))?.split('=')[1]
  console.log('\n  fetching corpus...')
  const cases = (await ensureCorpus()).filter((c) => only === undefined || c.date === only)

  const rows = []
  const stats = { calls: 0, errors: 0, lat: [], inTok: 0, outTok: 0 }

  for (const c of cases) {
    const truth = await readTruth(c.notes)
    const dests = await observe(c.pcaps)
    process.stdout.write(`  ${c.date}  ${c.label}: ${dests.length} destinations`)

    const answers = await pool(dests, CONCURRENCY, async (d) => {
      try {
        const r = await ask(d.state)
        stats.calls++
        stats.lat.push(r.latency)
        stats.inTok += r.usage?.input_tokens ?? 0
        stats.outTok += r.usage?.output_tokens ?? 0
        return r.answers
      } catch (error) {
        stats.errors++
        console.error(`\n    ${d.ip}: ${error.message}`)
        return undefined
      }
    })

    for (const [i, d] of dests.entries()) {
      const a = answers[i]
      if (a === undefined) continue
      const ioc = iocMatch(truth, d)
      rows.push({
        case: c.date, ip: d.ip, names: d.names,
        truth: ioc !== undefined, ioc,
        jev: suspicion(a),
        attacker: a.attacker_infra.noul,
        used: a.malware_used_it.noul,
        benign: a.benign_background.noul,
        label: a.label.choice,
        labelConf: a.label.confidence,
        base: baselineCall(d),
        state: d.state,
      })
    }
    console.log(`  -> ${rows.filter((r) => r.case === c.date && r.truth).length} named in the notes`)
  }

  if (rows.length === 0) {
    console.log('\n  no graded destinations\n')
    return
  }

  const jev = rates(rows, (r) => r.jev >= THRESHOLD)
  const base = rates(rows, (r) => r.base === 1)
  const labelRates = rates(rows, (r) => r.label === 'c2' || r.label === 'abused_service')

  const mean = (a) => a.reduce((x, y) => x + y, 0) / (a.length || 1)

  console.log(`\n  ${rows.length} destinations across ${cases.length} captures` +
    `  (${rows.filter((r) => r.truth).length} in the published IOCs)`)
  console.log(`  model ${MODEL}   ${stats.calls} calls${stats.errors ? `  (${stats.errors} errors)` : ''}` +
    `   mean ${mean(stats.lat).toFixed(0)}ms`)
  console.log(`  tokens ${stats.inTok} in / ${stats.outTok} out` +
    `   cost $${(stats.inTok / 1e6 * PER_MTOK).toFixed(4)}`)

  console.log(`\n  pilot                       precision   recall      F1     FP    FN`)
  const line = (name, r) => console.log(
    `  ${name.padEnd(26)}${pct(r.prec).padStart(9)}${pct(r.rec).padStart(11)}` +
    `${r.f1.toFixed(2).padStart(8)}${String(r.fp).padStart(7)}${String(r.fn).padStart(6)}`)
  line(`shipped heuristic`, base)
  line(`jev suspicion >= ${THRESHOLD}`, jev)
  line(`jev choice c2|abused`, labelRates)

  console.log(`\n  calibration -- P(infection) vs how often the notes named it\n`)
  console.log(`    P(infection)     n   predicted   observed`)
  for (let lo = 0; lo < 1; lo += 0.1) {
    const bin = rows.filter((r) => r.jev >= lo && r.jev < lo + 0.1 + (lo >= 0.9 ? 0.01 : 0))
    if (bin.length === 0) continue
    console.log(`    ${lo.toFixed(1)}-${(lo + 0.1).toFixed(1)}  ${String(bin.length).padStart(6)}` +
      `${mean(bin.map((r) => r.jev)).toFixed(2).padStart(12)}` +
      `${(bin.filter((r) => r.truth).length / bin.length).toFixed(2).padStart(11)}`)
  }
  console.log(`\n    base rate: ${(rows.filter((r) => r.truth).length / rows.length).toFixed(3)}`)

  // Thresholds belong on the user's data, not on 0.5. This sweep is what
  // defines the cascade's three bands: auto-accept, escalate, drop.
  console.log(`\n  threshold sweep -- where to cut for the slow tier\n`)
  console.log(`    cut    flagged   precision   recall    missed IOCs`)
  for (const t of [0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5]) {
    const r = rates(rows, (x) => x.jev >= t)
    console.log(`    ${t.toFixed(2)}${String(r.tp + r.fp).padStart(9)}${pct(r.prec).padStart(12)}` +
      `${pct(r.rec).padStart(9)}${String(r.fn).padStart(15)}`)
  }
  const keepAll = [...rows].sort((a, b) => a.jev - b.jev)
    .find((r) => r.truth)?.jev ?? 0
  const certain = rows.filter((r) => r.jev >= 0.25).length
  const dropped = rows.filter((r) => r.jev < keepAll).length
  console.log(`\n    lowest-scored real IOC: ${keepAll.toFixed(2)}` +
    `  -- below that, ${dropped} of ${rows.length} dests drop with no IOC lost`)
  console.log(`    at >= 0.25: ${certain} dests, ` +
    `${pct(rates(rows, (r) => r.jev >= 0.25).prec)} precision -- straight to the Plan`)
  console.log(`    the band between is what the slow tier reads`)

  const disagree = rows.filter((r) => (r.jev >= THRESHOLD ? 1 : 0) !== r.base)
  console.log(`\n  disagreements -- ${disagree.length} of ${rows.length}, and which pilot the notes back\n`)
  for (const r of disagree.sort((a, b) => Number(b.truth) - Number(a.truth))) {
    const jevSays = r.jev >= THRESHOLD ? 'infection' : 'benign'
    const baseSays = r.base === 1 ? 'infection' : 'benign'
    const winner = (r.jev >= THRESHOLD) === r.truth ? 'jev' : 'heuristic'
    console.log(`    ${r.case}  ${r.ip.padEnd(16)}${(r.names[0] ?? '-').slice(0, 34).padEnd(36)}` +
      `jev ${r.jev.toFixed(2)} ${jevSays.padEnd(10)} heuristic ${baseSays.padEnd(10)}` +
      `notes: ${r.truth ? `IOC (${r.ioc})` : 'not listed'}  -> ${winner}`)
  }

  const out = path.join(import.meta.dirname, 'results.json')
  await fs.writeFile(out, `${JSON.stringify({ model: MODEL, served: [...servedModels], threshold: THRESHOLD, stats, jev, base, labelRates, rows }, undefined, 2)}\n`)
  console.log(`\n  rows -> ${out}\n`)
}

await main()
