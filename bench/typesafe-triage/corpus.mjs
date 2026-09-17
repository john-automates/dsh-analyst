// The malware-traffic-analysis.net entries this bench grades against.
//
// Infection writeups only. The "seven days of scans and probes" entries are
// server-side traffic with no victim and no C2, so there is nothing to bind.
// Each entry publishes the infection's destinations in its notes file, which is
// the ground truth nothing else in this repo has.
export const CASES = [
  { date: '2026-09-10', page: '2026/09/10/index.html', label: 'Atomic macOS (AMOS) Stealer' },
  { date: '2026-09-08', page: '2026/09/08/index.html', label: 'XWorm' },
  { date: '2026-08-10', page: '2026/08/10/index.html', label: 'Lumma Stealer or variant' },
  { date: '2026-08-06', page: '2026/08/06/index.html', label: 'Remcos RAT 7.2.5 Pro' },
  { date: '2026-01-29', page: '2026/01/29/index.html', label: 'njRAT with MassLogger' },
  // Windows infections that also carry ordinary browsing, so precision is
  // measured against real background traffic and not an all-IOC capture.
  { date: '2026-08-21', page: '2026/08/21/index.html', label: 'SmartApeSG ClickFix -> two RATs' },
  { date: '2026-05-27', page: '2026/05/27/index.html', label: 'SmartApeSG ClickFix -> NetSupport RAT' },
]

export const SITE = 'https://www.malware-traffic-analysis.net'

/**
 * The site's published password scheme: `infected_` followed by the post date.
 * Stated on https://www.malware-traffic-analysis.net/about.html (as an image,
 * so it does not scrape).
 */
export function zipPassword(date) {
  return `infected_${date.replaceAll('-', '')}`
}
