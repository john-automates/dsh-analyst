// Fold the live session log into the data the investigation view renders.
//
// The harness appends each event as its own zstd frame, so the file is a
// concatenation of independent frames rather than one stream -- decompressing it
// means finding every frame header and decoding each in turn.
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'

const SESSIONS = path.join(process.env.HOME, '.dsh/sessions')

/** Every zstd frame in an appended session log, decoded and concatenated. */
function readSession(file) {
  const buf = fs.readFileSync(file)
  const starts = []
  for (let i = 0; i <= buf.length - 4; i++) {
    if (buf[i] === 0x28 && buf[i + 1] === 0xB5 && buf[i + 2] === 0x2F && buf[i + 3] === 0xFD) {
      starts.push(i)
    }
  }
  let text = ''
  for (const [k, at] of starts.entries()) {
    const end = k + 1 < starts.length ? starts[k + 1] : buf.length
    try {
      text += zlib.zstdDecompressSync(buf.subarray(at, end)).toString('utf8')
    } catch { /* a frame still being written */ }
  }
  return text.split('\n').filter((l) => l !== '').flatMap((l) => {
    try {
      return [JSON.parse(l)]
    } catch {
      return []
    }
  })
}

/** The newest session directory under a case path. */
function newestSession(caseDir) {
  const key = `-${caseDir.replaceAll('/', '-')}-`
  const root = fs.readdirSync(SESSIONS).find((d) => d.includes(path.basename(caseDir)))
  if (root === undefined) throw new Error(`no session for ${caseDir} (looked for ${key})`)
  const dir = path.join(SESSIONS, root)
  // Biggest log, not newest: a run spawns side sessions (title generation,
  // subagents) whose directories are touched later but hold a handful of events.
  const runs = fs.readdirSync(dir)
    .map((d) => path.join(dir, d, 'session.jsonl.zstd'))
    .filter((f) => fs.existsSync(f))
    .map((f) => ({ f, size: fs.statSync(f).size }))
    .sort((a, b) => b.size - a.size)
  if (runs.length === 0) throw new Error(`no session log under ${dir}`)
  return runs[0].f
}

const caseDir = process.argv[2] ?? 'bench/typesafe-triage/runs/2026-09-08'
const events = readSession(newestSession(path.resolve(caseDir)))

const last = (type) => [...events].reverse().find((e) => e.type === type)?.data
const all = (type) => events.filter((e) => e.type === type).map((e) => e.data)
// The `session` frame carries `createdAt`, not `time`; every later event has `time`.
const t0 = events.find((e) => e.type === 'session')?.createdAt
  ?? events.find((e) => typeof e.time === 'number')?.time ?? 0
const at = (e) => Math.round((e.time - t0) / 100) / 10

const calls = events.filter((e) => e.type === 'tool/call').map((e) => {
  let args = {}
  try {
    args = JSON.parse(e.data.arguments)
  } catch { /* non-JSON arguments */ }
  return { at: at(e), step: e.data.step, name: e.data.name, args, id: e.data.callId }
})

const results = new Map()
for (const e of events.filter((x) => x.type === 'tool/result')) {
  const c = e.data.message?.content?.[0]
  const text = c?.content?.map((p) => p.text ?? '').join('') ?? ''
  results.set(c?.toolCallId, { at: at(e), ok: !text.startsWith('Error:'), text: text.slice(0, 600) })
}

const data = {
  generated: Date.now(),
  session: events.find((e) => e.type === 'session'),
  finished: events.some((e) => e.type === 'turn/end'),
  mission: last('investigation/mission'),
  plan: last('investigation/plan'),
  bind: last('investigation/bind'),
  report: last('investigation/report'),
  identities: all('investigation/identity'),
  hunts: all('investigation/hunt'),
  actions: all('investigation/action'),
  steps: events.filter((e) => e.type === 'step/start').length,
  reasoningChunks: events.filter((e) => e.type === 'reasoning-chunks').length,
  textChunks: events.filter((e) => e.type === 'text-chunks').length,
  elapsed: Math.round((([...events].reverse().find((e) => typeof e.time === 'number')?.time ?? t0) - t0) / 1000),
  calls: calls.map((c) => ({ ...c, result: results.get(c.id) })),
  finalText: [...events].reverse().find((e) => e.type === 'assistant/message'
    && e.data?.message?.content?.some?.((p) => p.type === 'text'))
    ?.data?.message?.content?.filter((p) => p.type === 'text').map((p) => p.text).join('') ?? '',
}

const out = path.join(import.meta.dirname, 'view-data.json')
fs.writeFileSync(out, JSON.stringify(data))

// Inline the data into the page: an artifact cannot fetch a local file.
const tpl = fs.readFileSync(path.join(import.meta.dirname, 'view.template.html'), 'utf8')
const page = path.join(import.meta.dirname, 'view.html')
fs.writeFileSync(page, tpl.replace('"__DATA__"', JSON.stringify(data)))

console.log(`  ${events.length} events, ${data.steps} steps, ${data.calls.length} tool calls, ` +
  `${data.identities.length} identities, ${data.elapsed}s` +
  `${data.finished ? ', finished' : ', running'}`)
console.log(`  -> ${page}`)
