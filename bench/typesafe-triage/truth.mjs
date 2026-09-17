// Ground truth: the IOCs each malware-traffic-analysis.net post publishes.
//
// The notes file lists the domains, URLs, and IPs that belong to the infection.
// This is the only thing in the project with ground truth for a judgment -- the
// analyst plugin's CDN/update suffix list has never been graded against one.
//
// A destination seen in the capture is POSITIVE when its IP, or any name the
// capture resolved for it, appears in the notes. Hosts the notes name but the
// capture never contacted (sandbox links, mail relays in `Received:` headers)
// simply never come up, because grading starts from the capture, not the notes.
//
// Limitation, stated rather than hidden: a destination that was part of the
// infection but that the post did not list counts as a negative here. That is
// visible in the disagreement list rather than silently scored.
import fs from 'node:fs/promises'

/** Undo the usual defanging (`1.2.3[.]4`, `hxxps://`, `[:]`). */
function refang(text) {
  return text
    .replaceAll('[.]', '.').replaceAll('(.)', '.')
    .replaceAll('[:]', ':').replaceAll('[/]', '/')
    .replace(/hxxp/gi, 'http')
}

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
// A dotted name with a plausible TLD. Excludes file names (.js, .ps1, .rar...).
const HOST = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi
const NOT_A_TLD = new Set([
  'js', 'ps1', 'exe', 'dll', 'rar', 'zip', 'dat', 'txt', 'lnk', 'bat', 'vbs',
  'jpg', 'png', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'lzh', 'msi', 'iso',
  'php', 'html', 'htm', 'plist', 'sh', 'py', 'cmd', 'scr', 'pcap',
  'tar', 'gz', 'bz2', '7z', 'dmg', 'pkg', 'bin', 'sys', 'log', 'tmp',
  'cfg', 'ini', 'json', 'xml', 'csv', 'jar', 'apk', 'elf', 'macho',
])

/**
 * Hosts that appear in every post's boilerplate rather than in its traffic:
 * the sandboxes Brad links, and the site itself.
 */
const BOILERPLATE = [
  'joesandbox.com', 'tria.ge', 'any.run', 'app.any.run', 'virustotal.com',
  'malware-traffic-analysis.net', 'linkedin.com', 'github.com/malware-traffic',
  'bazaar.abuse.ch', 'urlhaus.abuse.ch', 'abuse.ch',
]

function isBoilerplate(host) {
  return BOILERPLATE.some((b) => host === b || host.endsWith(`.${b}`))
}

/** Parse one notes file into the IOC sets the bench grades against. */
export async function readTruth(file) {
  const raw = refang(await fs.readFile(file, 'utf8'))

  const ips = new Set()
  for (const m of raw.matchAll(IPV4)) {
    if (m[0].split('.').every((o) => Number(o) <= 255)) ips.add(m[0])
  }

  const hosts = new Set()
  for (const m of raw.matchAll(HOST)) {
    const host = m[0].toLowerCase().replace(/\.+$/, '')
    const tld = host.slice(host.lastIndexOf('.') + 1)
    if (NOT_A_TLD.has(tld)) continue
    // Reverse-DNS bundle identifiers out of file paths (`com.apple.accountsd`).
    if (host.startsWith('com.') || host.startsWith('org.') || host.startsWith('net.')) continue
    if (IPV4.test(host)) continue
    if (isBoilerplate(host)) continue
    hosts.add(host)
  }

  return { ips, hosts, text: raw }
}

/**
 * Whether a capture destination is one the post named.
 * @param truth - parsed notes.
 * @param dest - `{ ip, names }` from the observation.
 * @returns the matching IOC, or undefined.
 */
export function iocMatch(truth, dest) {
  if (truth.ips.has(dest.ip)) return dest.ip
  for (const name of dest.names) {
    const host = name.toLowerCase().replace(/\.+$/, '')
    if (truth.hosts.has(host)) return host
    // A post may list `example.com` while the capture saw `www.example.com`.
    for (const ioc of truth.hosts) {
      if (host.endsWith(`.${ioc}`) || ioc.endsWith(`.${host}`)) return ioc
    }
  }
  return undefined
}
