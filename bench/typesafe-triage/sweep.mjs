// Run a set of cases through the analyst harness, score each one, append.
//
//   node bench/typesafe-triage/sweep.mjs --build=<label> [options]
//
// Sweeps were assembled by hand four times before this existed, and each hand
// assembly got one of the grading disciplines wrong at least once: a capture
// kept its MTA name (which is the malware family, so the answer), `--build` was
// omitted (so the trend compared two harnesses and called the difference
// variance), or `no-web.cordis.yml` was forgotten (so the agent could search a
// corpus whose answers are published on the open web). Every one of those is
// enforced here rather than remembered.
//
// Options:
//   --build=<label>   REQUIRED. What harness this is. The session log carries no
//                     plugin config, so nothing else can recover it.
//   --cases=a,b,c     corpus slugs, in order. Default: every case with a capture.
//   --repeats=N       runs per case (default 2). One run measures nothing.
//   --parallel=N      concurrent investigations (default 1).
//   --tag=x           run-name infix, so a second sweep on one build does not
//                     collide with the first. Default: a UTC HHMM stamp.
//   --patch=a,b       extra overlays applied after the three below, in order.
//                     Repo-relative or absolute.
//   --env=K=V,K=V     env passed to each investigation. The `investigation`
//                     entry lives inside the analyst agent preset, not the
//                     profile tree, so a gate mounted there is reached this way
//                     rather than by `--patch`. For the groundedness gate:
//                     `--env=DSH_REQUIRE_GROUNDED_REPORT=1`.
//   --timeout=SEC     per-investigation kill (default 1800).
//   --dry-run         stage nothing, spend nothing, print the plan.
//
// Run names are `<slug>-<tag><repeat>`. They must be unique on disk AND in
// ~/.dsh/sessions: `scorecard.mjs` locates a run's session log by matching the
// run-dir basename, and picks the LARGEST log under any session directory that
// matches. Reusing a name silently scores an older, bigger session.
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { CASES } from './corpus.mjs'

const HERE = import.meta.dirname
const REPO = path.resolve(HERE, '../..')

/**
 * The task every graded investigation has been given, verbatim.
 *
 * Recovered from the session logs rather than retyped: the whole point of a
 * sweep is that the runs pool, and two runs given different prompts are not
 * repeats of each other. Change it and the old records stop comparing — which
 * is why its hash prints at the head of every sweep. The ledger does not carry
 * it: `scorecard.mjs` owns the record shape and reads only the session log.
 */
const PROMPT = 'Define the Investigation Question, then investigate the packet '
  + 'capture(s) in this case directory. Identify the infected host and the '
  + 'command-and-control infrastructure it contacted, bind that relationship, '
  + 'and write the case report.'

/**
 * Overlays applied after the profile's own layer, in order.
 *
 * `no-web` is not optional and is not a flag: see its header. A sweep that can
 * reach the open web is not a measurement of this corpus.
 */
const PATCHES = [
  'examples/analyst/headless.cordis.yml',
  'bench/typesafe-triage/deepseek-max.cordis.yml',
  'bench/typesafe-triage/no-web.cordis.yml',
].map((p) => path.join(REPO, p))

/**
 * Extra overlays under test, appended after the fixed three.
 *
 * A gate being measured is a patch, never an edit to the three above: the
 * fixed set is what makes a run comparable to every earlier one, and the extra
 * is what `--build` is naming.
 */
const EXTRA = (process.argv.find((a) => a.startsWith('--patch=')) ?? '')
  .slice(8).split(',').filter((p) => p !== '')
  .map((p) => (path.isAbsolute(p) ? p : path.join(REPO, p)))

/** Extra environment for each investigation, as `K=V` pairs. */
const EXTRA_ENV = Object.fromEntries(
  (process.argv.find((a) => a.startsWith('--env=')) ?? '').slice(6)
    .split(',').filter((pair) => pair.includes('='))
    .map((pair) => [pair.slice(0, pair.indexOf('=')), pair.slice(pair.indexOf('=') + 1)]),
)

const flag = (name, fallback) => {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`))
  return hit === undefined ? fallback : hit.slice(name.length + 3)
}
const has = (name) => process.argv.includes(`--${name}`)

const build = flag('build')
if (build === undefined || build === '') {
  throw new Error('--build=<label> is required: the session log carries no plugin config, '
    + 'so without it the trend compares different harnesses and reports the difference as variance')
}
const repeats = Number(flag('repeats', '2'))
const parallel = Number(flag('parallel', '1'))
const timeoutMs = Number(flag('timeout', '1800')) * 1000
const dryRun = has('dry-run')
const stamp = new Date().toISOString().slice(11, 16).replace(':', '')
const tag = flag('tag', stamp)

/** Every `.pcap`/`.pcapng` under `dir`, recursively, in stable order. */
async function pcapsUnder(dir) {
  const out = []
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    // 2026-08-06 ships its two captures inside a subdirectory, so a flat
    // readdir stages zero pcaps and the agent investigates an empty room.
    if (entry.isDirectory()) out.push(...await pcapsUnder(full))
    else if (/\.pcap(ng)?$/.test(entry.name)) out.push(full)
  }
  return out.sort()
}

const selected = flag('cases')
const wanted = selected === undefined
  ? CASES
  : selected.split(',').map((slug) => {
    const hit = CASES.find((c) => c.slug === slug.trim())
    if (hit === undefined) throw new Error(`unknown case slug '${slug}'; known: ${CASES.map((c) => c.slug).join(', ')}`)
    return hit
  })

/** Session directories already on disk, to refuse a run name that would alias one. */
const sessionDirs = await fs.readdir(path.join(os.homedir(), '.dsh/sessions')).catch(() => [])

const jobs = []
for (const kase of wanted) {
  const caseDir = path.join(HERE, 'cases', kase.date)
  const sources = await pcapsUnder(caseDir).catch(() => [])
  if (sources.length === 0) {
    console.error(`[sweep] skip ${kase.slug}: no capture under ${path.relative(REPO, caseDir)} — run fetch.mjs`)
    continue
  }
  for (let n = 1; n <= repeats; n++) {
    const name = `${kase.slug}-${tag}${n}`
    const runDir = path.join(HERE, 'runs', name)
    if (await fs.stat(runDir).then(() => true, () => false)) {
      throw new Error(`run dir ${name} already exists; pass a different --tag`)
    }
    if (sessionDirs.some((d) => d.endsWith(`${name}--`))) {
      throw new Error(`a session log already matches run name ${name}; pass a different --tag`)
    }
    jobs.push({ name, runDir, kase, sources })
  }
}

if (jobs.length === 0) throw new Error('nothing to run')

const promptSha = (await import('node:crypto'))
  .createHash('sha256').update(PROMPT).digest('hex').slice(0, 12)

console.log(`[sweep] build=${build} tag=${tag} repeats=${repeats} parallel=${parallel} `
  + `jobs=${jobs.length} prompt=${promptSha}`
  + (Object.keys(EXTRA_ENV).length > 0 ? ` env=${JSON.stringify(EXTRA_ENV)}` : ''))
for (const j of jobs) {
  console.log(`  ${j.name.padEnd(20)} ${j.kase.date}  ${j.sources.length} capture(s)  ${j.kase.label}`)
}
if (dryRun) {
  console.log(`\n[sweep] dry run. Each job would run, from its run dir:\n  pnpm dsh --profile headless \\\n`
    + [...PATCHES, ...EXTRA].map((p) => `    --patch ${path.relative(REPO, p)} \\\n`).join('')
    + `    "${PROMPT.slice(0, 60)}..."\n`
    + `  node bench/typesafe-triage/scorecard.mjs runs/<name> --case=<date> --build=${build}`)
  process.exit(0)
}

/** Stage the captures under neutral names, read-only. */
async function stage(job) {
  await fs.mkdir(job.runDir, { recursive: true })
  for (const [i, src] of job.sources.entries()) {
    // MTA names captures after the malware family, so the original filename
    // hands the agent the answer. `scorecard.mjs` records `captureNamesNeutral`
    // and `trend.mjs` refuses to pool a named run with a neutral one.
    const dest = path.join(job.runDir, `capture-${i + 1}${path.extname(src)}`)
    await fs.copyFile(src, dest)
    await fs.chmod(dest, 0o444)
  }
}

/** Run `cmd` to completion, streaming to `logFile`. Resolves with the exit code. */
function run(cmd, args, cwd, logFile, kill, env) {
  return new Promise((resolve, reject) => {
    // `detached` so the timeout can kill the whole tree. `pnpm dsh` is three
    // processes — pnpm, `sh -c`, and the node that actually spends tokens — and
    // SIGKILL to the parent alone leaves the investigation running unsupervised
    // with nothing left to score it.
    const child = spawn(cmd, args, { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] })
    const chunks = []
    child.stdout.on('data', (c) => chunks.push(c))
    child.stderr.on('data', (c) => chunks.push(c))
    let timedOut = false
    const timer = kill === undefined ? undefined : setTimeout(() => {
      timedOut = true
      try { process.kill(-child.pid, 'SIGKILL') } catch { child.kill('SIGKILL') }
    }, kill)
    child.on('error', reject)
    child.on('close', async (code) => {
      if (timer !== undefined) clearTimeout(timer)
      if (logFile !== undefined) await fs.writeFile(logFile, Buffer.concat(chunks))
      resolve({ code, timedOut, output: Buffer.concat(chunks).toString() })
    })
  })
}

const results = []

async function investigate(job) {
  const started = Date.now()
  await stage(job)
  // The log lives BESIDE the run dir, never inside it: the run dir is the
  // agent's writable workspace and it enumerates what is there.
  const log = path.join(HERE, 'runs', `${job.name}.log`)
  // DSH_CASE_DIR, not cwd. `pnpm` runs a workspace script with cwd set to the
  // package root, so spawning `pnpm dsh` from the run dir silently hands the
  // agent the REPO as its session workspace: the first attempt at this read
  // `bench/typesafe-triage/cases/` with the original MTA filenames, found the
  // notes files, and reasoned "the four IPs match the handoff" before it was
  // killed. `headless.cordis.yml` reads DSH_CASE_DIR first for exactly this.
  const dsh = await run(
    'pnpm',
    ['dsh', '--profile', 'headless', ...[...PATCHES, ...EXTRA].flatMap((p) => ['--patch', p]), PROMPT],
    job.runDir, log, timeoutMs, { ...process.env, ...EXTRA_ENV, DSH_CASE_DIR: job.runDir },
  )
  // A session log named after anything but the run dir means the workspace was
  // not the case directory, which makes the run contaminated rather than merely
  // failed. Refuse to score it, and say so loudly enough to stop the sweep.
  const sessions = await fs.readdir(path.join(os.homedir(), '.dsh/sessions')).catch(() => [])
  if (!sessions.some((d) => d.endsWith(`${job.name}--`))) {
    console.error(`[sweep] ${job.name}: NO SESSION scoped to the run dir — the workspace was not `
      + `the case directory. Not scored; discard anything it wrote.`)
    results.push({ name: job.name, scored: false })
    return
  }
  const mins = ((Date.now() - started) / 60000).toFixed(1)
  if (dsh.timedOut) {
    console.error(`[sweep] ${job.name}: KILLED after ${mins}m`)
  } else if (dsh.code !== 0) {
    console.error(`[sweep] ${job.name}: dsh exited ${dsh.code} after ${mins}m (see runs/${job.name}.log)`)
  } else {
    console.log(`[sweep] ${job.name}: investigation done in ${mins}m`)
  }
  // Score regardless of exit code: `closed: false` is a result, not an absence
  // of one. Only a missing session log — dsh died before writing — has nothing
  // to score, and that must not take the rest of the sweep down with it.
  const scored = await run(
    process.execPath,
    [path.join(HERE, 'scorecard.mjs'), job.runDir, `--case=${job.kase.date}`, `--build=${build}`],
    REPO, undefined, undefined,
  )
  if (scored.code !== 0) {
    console.error(`[sweep] ${job.name}: NOT SCORED — ${scored.output.trim().split('\n').pop()}`)
    results.push({ name: job.name, scored: false })
    return
  }
  const record = JSON.parse(scored.output)
  results.push({ name: job.name, scored: true, record })
  const b = record.bench ?? {}
  console.log(`[sweep] ${job.name}: closed=${record.production.closed} `
    + `C2=${b.c2Correct === true ? 'Y' : 'n'} IOC=${b.iocCoveragePct ?? '-'}% `
    + `grounded=${record.production.groundedPct ?? '-'}% $${record.production.costUsd}`)
}

/** A fixed pool rather than a chunked batch, so one slow case never idles the rest. */
const queue = [...jobs]
await Promise.all(Array.from({ length: Math.max(1, parallel) }, async () => {
  for (let job = queue.shift(); job !== undefined; job = queue.shift()) {
    await investigate(job).catch((error) => {
      console.error(`[sweep] ${job.name}: ${String(error)}`)
      results.push({ name: job.name, scored: false })
    })
  }
}))

const ok = results.filter((r) => r.scored)
const spend = ok.reduce((sum, r) => sum + (r.record.production.costUsd ?? 0), 0)
console.log(`\n[sweep] ${ok.length}/${jobs.length} scored, $${spend.toFixed(4)} total.`)
if (ok.length < jobs.length) {
  console.log(`[sweep] unscored: ${results.filter((r) => !r.scored).map((r) => r.name).join(', ')}`)
}
console.log(`[sweep] node bench/typesafe-triage/trend.mjs`)
