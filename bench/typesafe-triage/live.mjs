// A live view of the investigation, served from this machine.
//
// The session log is the agent's own stream: `reasoning-chunks` carries the
// model's thinking token by token, `tool-call-chunks` carries each call's
// arguments as they are typed, and the `investigation/*` events are the ledger
// filling in. This tails that file and pushes every new event to the browser
// over SSE, so the page shows what the model is doing while it does it.
//
// It is served from localhost because a published page cannot reach your
// machine. Nothing here talks to the network.
//
//   node bench/typesafe-triage/live.mjs [case-dir]
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import zlib from 'node:zlib'

const PORT = Number(process.env.LIVE_PORT ?? 7100)
const SESSIONS = path.join(process.env.HOME, '.dsh/sessions')
const caseDir = path.resolve(process.argv[2] ?? 'bench/typesafe-triage/runs/2026-09-08')

/** The busiest session log under a case directory; side sessions are tiny. */
function findLog() {
  const root = fs.readdirSync(SESSIONS).find((d) => d.includes(path.basename(caseDir)))
  if (root === undefined) return undefined
  const dir = path.join(SESSIONS, root)
  const logs = fs.readdirSync(dir)
    .map((d) => path.join(dir, d, 'session.jsonl.zstd'))
    .filter((f) => fs.existsSync(f))
    .map((f) => ({ f, size: fs.statSync(f).size }))
    .sort((a, b) => b.size - a.size)
  return logs[0]?.f
}

/**
 * Frame starts in an appended zstd log. Each append is its own frame, so the
 * file is a concatenation rather than one stream.
 */
function frameStarts(buf) {
  const out = []
  for (let i = 0; i <= buf.length - 4; i++) {
    if (buf[i] === 0x28 && buf[i + 1] === 0xB5 && buf[i + 2] === 0x2F && buf[i + 3] === 0xFD) out.push(i)
  }
  return out
}

const clients = new Set()
let events = []          // everything decoded so far, in order
let doneFrames = 0       // frames already decoded

function poll() {
  const log = findLog()
  if (log === undefined) return
  let buf
  try {
    buf = fs.readFileSync(log)
  } catch {
    return
  }
  const starts = frameStarts(buf)
  // Decode only frames with a successor: the last one may still be mid-write.
  const fresh = []
  for (let k = doneFrames; k < starts.length - 1; k++) {
    try {
      const text = zlib.zstdDecompressSync(buf.subarray(starts[k], starts[k + 1])).toString('utf8')
      for (const line of text.split('\n')) {
        if (line === '') continue
        try {
          fresh.push(JSON.parse(line))
        } catch { /* partial line */ }
      }
    } catch { /* unreadable frame */ }
    doneFrames = k + 1
  }
  if (fresh.length === 0) return
  events = events.concat(fresh)
  const payload = `data: ${JSON.stringify(fresh)}\n\n`
  for (const c of clients) c.write(payload)
}

setInterval(poll, 250)

const PAGE = fs.readFileSync(path.join(import.meta.dirname, 'live.html'), 'utf8')

http.createServer((req, res) => {
  if (req.url === '/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    })
    // Replay what has already happened, then stream the rest.
    res.write(`data: ${JSON.stringify(events)}\n\n`)
    clients.add(res)
    req.on('close', () => clients.delete(res))
    return
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(PAGE)
}).listen(PORT, '127.0.0.1', () => {
  console.log(`\n  live view   http://localhost:${PORT}`)
  console.log(`  case        ${caseDir}`)
  console.log(`  log         ${findLog() ?? '(waiting for a session)'}\n`)
})
