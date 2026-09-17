// The fast tier, as the slow tier consumes it.
//
// Jev scores every outbound destination in a capture and this prints the
// ranked shortlist as plain text, to be handed to the analyst agent as the
// starting hypotheses its Plan needs. Nothing from the notes file is read: the
// slow tier must still prove the bind from packets.
//
//   node bench/typesafe-triage/triage.mjs <case-dir-or-pcap>
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { observe } from './observe.mjs'

const API = 'https://api.typesafe.ai/v1/systemone'
const MODEL = process.env.TYPESAFE_MODEL ?? 'jev-latest'

const KEY = (process.env.TYPESAFE_API_KEY ??
  await fs.readFile(path.join(os.homedir(), '.config/typesafe/api_key'), 'utf8')).trim()

const QUESTIONS = {
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
      'legitimate, widely used service.',
  },
  benign_background: {
    type: 'noul',
    instructions:
      'This is ordinary background traffic of no interest to an incident ' +
      'responder: a content delivery network, an operating-system or browser ' +
      'update or telemetry endpoint, an ad or analytics beacon, a font or asset ' +
      'host, or a certificate revocation check.',
  },
}

const suspicion = (a) =>
  Math.max(a.attacker_infra.noul, a.malware_used_it.noul) * (1 - a.benign_background.noul)

async function ask(state) {
  const r = await fetch(API, {
    method: 'POST',
    headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: MODEL, state, questions: QUESTIONS }),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 160)}`)
  return await r.json()
}

const target = process.argv[2]
if (target === undefined) throw new Error('usage: triage.mjs <case-dir-or-pcap>')

const stat = await fs.stat(target)
const pcaps = stat.isDirectory()
  ? (await fs.readdir(target)).filter((f) => /\.pcap(ng)?$/.test(f)).map((f) => path.join(target, f))
  : [target]

const dests = await observe(pcaps)
let inTok = 0
const scored = []
for (const d of dests) {
  const r = await ask(d.state)
  inTok += r.usage?.input_tokens ?? 0
  scored.push({ d, p: suspicion(r.answers), a: r.answers })
}
scored.sort((a, b) => b.p - a.p)

const lines = scored.map(({ d, p }, i) => {
  const names = d.names.length > 0 ? ` (${d.names.slice(0, 2).join(', ')})` : ''
  const ports = d.state.destination_ports.join('/')
  return `${i + 1}. ${d.ip}${names} port ${ports} — P(attacker infrastructure) ${p.toFixed(2)}`
})

console.log(lines.join('\n'))
console.error(`\n[triage] ${scored.length} destinations, ${inTok} input tokens, ` +
  `$${(inTok / 1e6 * 0.042).toFixed(5)}`)
