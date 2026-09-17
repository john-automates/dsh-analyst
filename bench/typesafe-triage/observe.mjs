// Turn a capture into one semantic observation per outbound destination.
//
// The analogue of agar's `state.js`: code does the extraction and the bucketing,
// so the judgment the model is asked is small, bounded, and the same one the
// hand-coded baseline gets. Nothing here is generated -- every field is read out
// of the packets by tshark.
//
// What deliberately does NOT go into the state: the capture's file name (MTA
// names captures after the malware family, which would hand the answer over) and
// anything from the notes file.
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { isLanIpv4 } from './baseline.mjs'

const run = promisify(execFile)
const TSHARK = process.env.TSHARK_BIN ?? 'tshark'

async function tshark(file, args) {
  const { stdout } = await run(TSHARK, ['-r', file, '-n', ...args], {
    maxBuffer: 256 * 1024 * 1024,
  })
  return stdout.split('\n').filter((l) => l !== '')
}

const fields = (...names) => ['-T', 'fields', '-E', 'separator=\t', ...names.flatMap((n) => ['-e', n])]

function bucketBytes(n) {
  if (n < 2_000) return 'a few hundred bytes'
  if (n < 50_000) return 'a few KB'
  if (n < 1_000_000) return 'tens to hundreds of KB'
  if (n < 10_000_000) return 'several MB'
  return 'tens of MB'
}

function bucketCount(n) {
  if (n === 1) return '1'
  if (n <= 5) return '2-5'
  if (n <= 20) return '6-20'
  if (n <= 100) return '21-100'
  return 'over 100'
}

function bucketSpan(seconds) {
  if (seconds < 2) return 'a single burst'
  if (seconds < 30) return 'under 30 seconds'
  if (seconds < 300) return 'a few minutes'
  return 'most of the capture'
}

/** Destinations a LAN host contacted, with the names and requests seen for each. */
export async function observe(pcaps) {
  const dests = new Map()   // dest ip -> accumulator
  const dnsNames = new Map() // resolved ip -> Set(name)

  for (const file of pcaps) {
    for (const line of await tshark(file, [
      ...fields('ip.src', 'ip.dst', 'tcp.dstport', 'udp.dstport', 'frame.len', 'frame.time_relative'),
    ])) {
      const [src, dst, tport, uport, len, t] = line.split('\t')
      if (src === undefined || dst === undefined || src === '' || dst === '') continue
      // Outbound only: a LAN source talking to something off the LAN.
      const outbound = isLanIpv4(src) && !isLanIpv4(dst)
      const inbound = isLanIpv4(dst) && !isLanIpv4(src)
      if (!outbound && !inbound) continue
      const ip = outbound ? dst : src
      const d = dests.get(ip) ?? {
        ip, lanHosts: new Set(), ports: new Set(), names: new Set(),
        requests: [], agents: new Set(), out: 0, in: 0, frames: 0,
        first: Infinity, last: 0,
      }
      d.lanHosts.add(outbound ? src : dst)
      const port = tport !== '' ? tport : uport
      if (outbound && port !== undefined && port !== '') d.ports.add(Number(port))
      const bytes = Number(len)
      if (outbound) d.out += bytes
      else d.in += bytes
      d.frames += 1
      const at = Number(t)
      if (at < d.first) d.first = at
      if (at > d.last) d.last = at
      dests.set(ip, d)
    }

    // Names: DNS answers, TLS SNI, and HTTP Host headers.
    for (const line of await tshark(file, ['-Y', 'dns.flags.response == 1',
      ...fields('dns.qry.name', 'dns.a')])) {
      const [name, addrs] = line.split('\t')
      if (name === undefined || addrs === undefined || addrs === '') continue
      for (const ip of addrs.split(',')) {
        const set = dnsNames.get(ip) ?? new Set()
        set.add(name.toLowerCase())
        dnsNames.set(ip, set)
      }
    }
    for (const line of await tshark(file, ['-Y', 'tls.handshake.extensions_server_name',
      ...fields('ip.dst', 'tls.handshake.extensions_server_name')])) {
      const [ip, sni] = line.split('\t')
      if (sni !== undefined && sni !== '') dests.get(ip)?.names.add(sni.toLowerCase())
    }
    for (const line of await tshark(file, ['-Y', 'http.request',
      ...fields('ip.dst', 'http.host', 'http.request.method', 'http.request.uri', 'http.user_agent')])) {
      const [ip, host, method, uri, agent] = line.split('\t')
      const d = dests.get(ip)
      if (d === undefined) continue
      if (host !== undefined && host !== '') d.names.add(host.toLowerCase())
      if (uri !== undefined && uri !== '') {
        const req = `${method} ${uri.length > 90 ? `${uri.slice(0, 90)}...` : uri}`
        if (!d.requests.includes(req)) d.requests.push(req)
      }
      if (agent !== undefined && agent !== '') d.agents.add(agent.slice(0, 80))
    }
  }

  for (const [ip, names] of dnsNames) {
    for (const n of names) dests.get(ip)?.names.add(n)
  }

  const start = Math.min(...[...dests.values()].map((d) => d.first))
  return [...dests.values()]
    .filter((d) => d.frames >= 2)
    .sort((a, b) => a.first - b.first)
    .map((d) => ({
      ip: d.ip,
      names: [...d.names],
      lanHosts: [...d.lanHosts],
      // The semantic state the model and the baseline both see.
      state: {
        destination_ip: d.ip,
        names_seen_for_it: [...d.names].slice(0, 4),
        destination_ports: [...d.ports].sort((a, b) => a - b).slice(0, 6),
        bytes_sent_to_it: bucketBytes(d.out),
        bytes_received_from_it: bucketBytes(d.in),
        packets: bucketCount(d.frames),
        contact_window: bucketSpan(d.last - d.first),
        first_contacted: d.first - start < 5
          ? 'at the very start of the capture'
          : `${Math.round(d.first - start)} seconds into the capture`,
        ...(d.requests.length > 0 ? { http_requests: d.requests.slice(0, 6) } : {}),
        ...(d.agents.size > 0 ? { http_user_agents: [...d.agents].slice(0, 2) } : {}),
      },
    }))
}
