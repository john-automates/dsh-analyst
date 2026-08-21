/**
 * Synthetic Mission + Plan that satisfies leftover-extras gates.
 * LAN 10.0.10.2, C2 198.51.100.80, CDN dest 203.0.113.80.
 */
import type { Session } from '@deepseek-ai/dsh-session'
import type Investigation from '../src/index.ts'
import { chassisMission } from '../src/mindset.ts'

const LAN = '10.0.10.2'
const C2 = '198.51.100.80'
const CDN_DEST = '203.0.113.80'

/**
 * Stamp a chassis Mission (cue validated) and append-only Plan.
 * Inventory names the case pcap. Hypotheses are one C2 and one CDN
 * alternative. Bind and auto-hunts need this Plan.
 * @param investigation - live investigation service.
 * @param session - session to append to.
 */
export function stampReadyMindset(investigation: Investigation, session: Session): void {
  investigation.recordMission(session, {
    ...chassisMission(),
    slots: { '0a': { value: 'valid' } },
    cue: { addr: C2, evidence_id: 'conv-1' },
    cueValidation: 'valid',
  })
  investigation.recordPlan(session, {
    inventory: ['evidence/a.pcap'],
    gaps: ['C2 domain unknown'],
    hypotheses: [
      {
        id: 'h-c2',
        claim: `I believe ${C2} is C2 because ${LAN} talks to that non-LAN cue`,
        disconfirm: 'SNI is a CDN or update name or the peer is a LAN DC',
        label: 'c2',
      },
      {
        id: 'h-cdn',
        claim: `I believe ${CDN_DEST} is CDN because update.microsoft.com is evidenced there`,
        disconfirm: 'a non-CDN dotted name is evidenced on that IP',
        label: 'cdn',
      },
    ],
  })
}
