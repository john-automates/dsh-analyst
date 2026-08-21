# Agent Note: Stamp MAC evidence_id from the talking IP, not the hunt subject

Status: implemented

English | [中文](2026-08-21-stamp-mac-evidence-from-talking-ip.zh.md)

## Problem

Live lumma-r11 (`a448b28`) bound the cited conversation correctly. Hostname donate from [victim-IP-scoped donate](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) worked (other hostnames on the ledger; victim hostname still landed). Close bar 4/5 — MAC FAIL. The gold MAC was ledger-tagged `evidence_id` of the DC from the first harvest and never restamped onto the victim. The model later saw that same MAC on the victim IP in tshark. DC MAC and gateway MAC stayed off the victim row. Session donate-notice count 0.

`harvestIdentities` stamped `evidence_id = scopeIp` (the hunt subject) on every harvested MAC. The first dump was scoped to the DC, so the workstation MAC locked to the DC. `recordIdentity` is unique on kind+value, so later victim-IP dumps do not restamp. `scopedIpForIdentity` treated hunt-subject `evidence_id` as affiliation and donated to the DC, not the victim. `identityDonatesToVictim` also refused when that `evidence_id` named a non-victim endpoint.

## Decision

A harvested MAC stamps `evidence_id` from the talking IPv4 that sources that `eth.src` on the line: labeled `ip.src`, outbound `ip → peer`, or ARP `is at`. When those IPs disagree, the talking IP wins. A field-only `eth.src` dump with no talking IP stamps hunt-subject `scopeIp` ([victim-IP-scoped restamp](2026-08-21-restamp-victim-ip-scoped-eth-src.md)). Hostname still stamps hunt-subject `evidence_id` from a `name-service` dump.

After a live bind, a MAC first seen under a DC or peer hunt still donates to the victim when any tool-result frame sources that MAC from the bound victim IP. Hunt-subject `evidence_id` does not veto that. The persisted who/where carry that mac. A DC or gateway MAC that never appears as `eth.src` sourced from the victim IP does not donate. Slots are not invented.

[Victim-IP-scoped donate](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) still donates hostname from hunt-subject `evidence_id` or a name-service line. Cue-as-victim stays refused and still issues [other-end](2026-08-21-other-end-hunt-on-cue-victim.md). Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and idle or DC LAN row.

## Alternatives considered

**Keep stamping hunt-subject `evidence_id` on MAC and teach donate to ignore it.** Rejected for harvest: the first write is durable. Stamping the talking IP records who sourced the frame. Donate still ignores a wrong first stamp when later frames source the MAC from the victim.

**Restamp `evidence_id` on a later victim-IP dump that already has a talking-IP or other IPv4 stamp.** Rejected here: talking IP still wins on the line, and donate already reads later victim-IP frames. Filling a missing first-harvest `evidence_id` from a field-only victim-IP-scoped dump is [victim-IP-scoped restamp](2026-08-21-restamp-victim-ip-scoped-eth-src.md). Overwrite of a filled DC/peer stamp is [overwrite DC MAC stamp](2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.md).

**Donate every MAC that shares any line with the victim IP (`ip.addr`).** Rejected: inbound frames contribute the far-side or DC NIC. Sourced means `ip.src`, outbound `ip → peer`, or ARP `is at`.

**Donate a DC or gateway MAC that never appears as eth.src on the victim IP.** Rejected: those NICs stay off the victim row.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP, a TEST-NET peer, and an idle or DC LAN row.

## Testing

`packages/analyst/investigation/tests/harvest.spec.ts` feeds a synthetic LAN client (`10.0.10.2`), TEST-NET peer (`198.51.100.80`), and idle or DC row (`10.0.10.3`). A MAC on a line whose talking IP is `10.0.10.2` stamps that IP even when `scopeIp` is `10.0.10.3`. Hostname still stamps the hunt subject. A field-only `eth.src` dump stamps hunt-subject `evidence_id` when the line has no talking IP ([victim-IP-scoped restamp](2026-08-21-restamp-victim-ip-scoped-eth-src.md)).

`packages/analyst/investigation/tests/bind.spec.ts` records a client MAC with `evidence_id=10.0.10.3`, then evidence text `eth.src` on `ip.src=10.0.10.2`. After a live bind, that MAC donates and persists on who/where. A DC MAC that never appears on `10.0.10.2` does not donate. Hostname donate and cue-as-victim refusal stay.

## Consequences

A DC-scoped first harvest cannot lock a workstation MAC to the DC when the frame names a different talking IP. A wrong first stamp still donates if later frames source that MAC from the bound victim. Hostname donate is unchanged. User and full_name stamp the conversation client ([conversation-client stamp](2026-08-21-stamp-user-fullname-from-conversation-client.md)).
