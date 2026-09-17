// Download the corpus: for each case, the infection pcap and the notes file.
//
// Only those two. `files-from-*` and `malware*` zips on the same pages hold live
// samples; this bench never downloads them, so nothing here can be executed by
// accident. Captures land outside the repo tree by default.
import { execFile } from 'node:child_process'
import fs from 'node:fs/promises'
import path from 'node:path'
import { promisify } from 'node:util'
import { CASES, SITE, zipPassword } from './corpus.mjs'

const run = promisify(execFile)

export const CASE_DIR = process.env.BENCH_CASE_DIR ??
  path.join(import.meta.dirname, 'cases')

async function get(url) {
  const r = await fetch(url)
  if (!r.ok) throw new Error(`HTTP ${r.status} for ${url}`)
  return r
}

/** Pull the pcap and notes zip names off an entry page. */
async function entryFiles(page) {
  const html = await (await get(`${SITE}/${page}`)).text()
  const dir = page.slice(0, page.lastIndexOf('/'))
  const names = [...html.matchAll(/href="([^"]+\.zip)"/g)].map((m) => m[1])
  // Never `files-from-*` or `malware*`: those hold live samples. Some entries
  // bundle several captures in one `...-traffic-2-pcaps.zip`.
  const capture = (n) => /pcap|traffic/i.test(n) && !/files|malware/i.test(n)
  const pcap = names.find((n) => /traffic\.pcap\.zip$/.test(n)) ?? names.find(capture)
  // Named `...-notes.txt.zip` on recent posts, `...-IOCs-from-*.txt.zip` earlier.
  const notes = names.find((n) => /notes\.txt\.zip$/.test(n)) ??
    names.find((n) => /\.txt\.zip$/.test(n))
  if (pcap === undefined || notes === undefined) {
    throw new Error(`${page}: no pcap/notes pair (found ${names.join(', ')})`)
  }
  return { dir, pcap, notes }
}

async function download(url, dest) {
  const buf = Buffer.from(await (await get(url)).arrayBuffer())
  await fs.writeFile(dest, buf)
  return buf.length
}

/** Extract one zip with the date-derived password, into `into`. */
async function unzip(zip, into, password) {
  await run('unzip', ['-o', '-q', '-P', password, '-d', into, zip])
}

/** Captures anywhere under a case directory; some zips extract a subfolder. */
async function findPcaps(dir) {
  const out = []
  for (const e of await fs.readdir(dir, { withFileTypes: true, recursive: true })) {
    if (e.isFile() && /\.pcap(ng)?$/.test(e.name)) out.push(path.join(e.parentPath, e.name))
  }
  return out
}

export async function ensureCorpus({ log = console.log } = {}) {
  await fs.mkdir(CASE_DIR, { recursive: true })
  const out = []
  for (const c of CASES) {
    const into = path.join(CASE_DIR, c.date)
    await fs.mkdir(into, { recursive: true })
    let pcaps = await findPcaps(into)
    let notes = (await fs.readdir(into)).find((f) => f.endsWith('.txt'))

    if (pcaps.length === 0 || notes === undefined) {
      const { dir, pcap: pz, notes: nz } = await entryFiles(c.page)
      const pw = zipPassword(c.date)
      for (const name of [pz, nz]) {
        const zip = path.join(into, name)
        const bytes = await download(`${SITE}/${dir}/${name}`, zip)
        await unzip(zip, into, pw)
        await fs.rm(zip)
        log(`  ${c.date}  ${name}  ${(bytes / 1e6).toFixed(1)}MB`)
      }
      pcaps = await findPcaps(into)
      notes = (await fs.readdir(into)).find((f) => f.endsWith('.txt'))
    }
    if (pcaps.length === 0 || notes === undefined) {
      // Some posts ship only decoded HTTPS text, no capture. Skip, don't abort.
      log(`  ${c.date}: no capture published, skipped`)
      continue
    }
    out.push({
      ...c,
      pcaps: pcaps.sort(),
      notes: path.join(into, notes),
    })
  }
  return out
}

if (process.argv[1] === import.meta.filename) {
  const cases = await ensureCorpus()
  console.log(`\n  ${cases.length} cases in ${CASE_DIR}\n`)
  for (const c of cases) console.log(`  ${c.date}  ${c.label}`)
  console.log()
}
