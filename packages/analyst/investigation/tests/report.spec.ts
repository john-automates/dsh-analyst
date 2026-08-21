import { describe, expect, it } from 'vitest'
import { identityOf } from '../src/harvest.ts'
import { c2TalkingLanVictim } from '../src/index.ts'

const LAN = '10.0.10.2'
const LAN_IDLE = '10.0.10.3'
const C2 = '198.51.100.80'
const CLIENT_MAC = '02:00:00:00:00:0a'
const C2_MAC = '02:00:00:00:00:cc'

const lan = identityOf('ip', LAN)!
const idle = identityOf('ip', LAN_IDLE)!
const c2 = identityOf('ip', C2)!
const clientMac = identityOf('mac', CLIENT_MAC)!
const remoteMac = identityOf('mac', C2_MAC)!

const conversation = `${LAN} → ${C2} TCP`

describe('C2-talking LAN helper', () => {
  it('resolves a unique ledger LAN IP that shares the ledger with a non-LAN peer', () => {
    expect(c2TalkingLanVictim([lan, c2, clientMac])).toEqual({ ip: LAN, mac: CLIENT_MAC })
    expect(c2TalkingLanVictim([lan, c2])).toEqual({ ip: LAN })
    expect(c2TalkingLanVictim([lan, idle, c2])).toBeUndefined()
    expect(c2TalkingLanVictim([lan])).toBeUndefined()
    expect(c2TalkingLanVictim([c2, clientMac])).toBeUndefined()
    expect(c2TalkingLanVictim([lan, c2, identityOf('ip', '127.0.0.1')!])).toEqual({ ip: LAN })
    expect(c2TalkingLanVictim([])).toBeUndefined()
  })

  it('prefers c2TalkingLanIps over an idle LAN on the ledger', () => {
    expect(c2TalkingLanVictim([idle, lan, c2], conversation)).toEqual({ ip: LAN })
    expect(c2TalkingLanVictim([], conversation)).toEqual({ ip: LAN })
    expect(c2TalkingLanVictim([lan, c2, clientMac, remoteMac], conversation)).toEqual({ ip: LAN })
  })
})
