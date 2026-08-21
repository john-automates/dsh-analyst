# Agent Note: Restamp victim-IP-scoped eth.src onto the victim row

Status: implemented

English | [中文](2026-08-21-restamp-victim-ip-scoped-eth-src.zh.md)

## Problem

Live lumma-r17 (`e964637`) bound the cited conversation correctly (victim `10.1.21.58` / c2 `153.92.1.49`). Close bar 4/5. [Persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md) filled ip/hostname/user/full_name. `mac` was not filled. The gold MAC was ledger-only with no `evidence_id`. A victim-IP `eth.src` hunt ran, but the dump had no same-line `ip.src` / outbound / ARP, so [talking-IP donate](2026-08-21-stamp-mac-evidence-from-talking-ip.md) did not fire. Three ledger MACs blocked unique-unaffiliated. Persist writes only a donated victim-IP MAC, so it wrote nothing. DC and gateway MACs stayed off accepted who/where.

A field-only `eth.src` dump scoped to the victim IP does not stamp talking-IP `evidence_id` (no `ip.src` on the line). The first harvest of that MAC is unaffiliated. Donate required same-line `ip.src` or uniqueness. `recordIdentity` unique-on-kind+value kept the empty first stamp. After bind, that MAC never affiliated to the victim row.

## Decision

After a live bind, restamp `eth.src` from the victim-IP hunt onto the victim row, then persist that mac on who/where.

An `eth-src` hunt or dump scoped to an IPv4 (`scopeIp`, `display_filter` `ip.addr` / `ip.src ==` that IP) stamps harvested `eth.src` `evidence_id` as that IP when the line has no talking IP. Talking IP still wins when the line has `ip.src`, outbound `ip → peer`, or ARP `is at`. After a live bind, if that IP is the victim, the MAC donates to the victim row.

Whole-ledger uniqueness and a missing first-harvest `evidence_id` do not block a MAC that appears on victim-IP frames or in a victim-IP-scoped `eth.src` dump. `recordIdentity` unique-on-kind+value still yields one row; a later event may fill a missing `evidence_id`.

A DC or gateway MAC that never shares those victim-IP frames or victim-scoped dumps stays off. An `eth-src` hunt scoped to the DC does not donate those MACs to the victim.

Accepted who/where are still `completeAcceptedSlot` of that projected row. Donated mac is persisted when the model omits the key. ip/hostname/user/full_name stay. Both-LAN refuse and bind coerce stay. Slots are not invented.

[Talking-IP MAC stamp](2026-08-21-stamp-mac-evidence-from-talking-ip.md) still owns same-line donate. [Persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md) still owns fill-on-omit. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and LAN DC.

## Alternatives considered

**Keep refusing hunt-subject `evidence_id` on every field-only `eth.src` dump.** Rejected: a victim-IP-scoped field-only dump is the hunt that names the talking IP. Leaving `evidence_id` empty makes donate require same-line `ip.src` or uniqueness, which the live dump does not provide.

**Keep `recordIdentity` unique-on-kind+value with no restamp, and teach donate to parse hunt filters out of evidence text.** Rejected: auto-run dump text is `eth.src: MAC` only. The scope lives on the hunt / `display_filter`, which harvest already receives as `scopeIp`. Folding a later `evidence_id` onto the first-seen row records that scope.

**Overwrite an existing talking-IP or DC `evidence_id` with a later scoped dump.** Rejected: talking IP still wins on the line. A DC-scoped first stamp stays; donate already ignores it when later frames source the MAC from the victim. This change only fills a missing first-harvest `evidence_id`.

**Donate a DC or gateway MAC that never appears on victim-IP frames or in a victim-IP-scoped dump.** Rejected: those NICs stay off the victim row.

**Invent a MAC, drop ip/hostname/user/full_name, bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: persist still copies only donated slots. The fixture is a synthetic LAN client, TEST-NET peer, and LAN DC.

## Testing

`packages/analyst/investigation/tests/harvest.spec.ts` feeds a synthetic LAN client (`10.0.10.2`), TEST-NET peer (`198.51.100.80`), and LAN DC (`10.0.10.3`). A field-only `eth.src` dump with `scopeIp=10.0.10.2` stamps that IP. Talking IP still wins when the line has `ip.src`. Same-line donate stays.

`packages/analyst/investigation/tests/bind.spec.ts` first harvests `CLIENT_MAC` with no `evidence_id`, then a field-only `eth.src: CLIENT_MAC` dump with `scopeIp=10.0.10.2` plus a DC MAC on a DC-scoped dump. After a live bind, who/where that omit `mac` persist `CLIENT_MAC`. The DC MAC stays off. Three unaffiliated MACs donate none unless one appears on the victim-IP-scoped dump.

`packages/analyst/investigation/tests/investigation.spec.ts` records `CLIENT_MAC` with no `evidence_id`, then a scoped `pcap_filter` field-only dump restamps that row. A later DC-scoped restamp does not overwrite the victim stamp.

## Consequences

A victim-IP-scoped field-only `eth.src` dump affiliates that MAC to the victim after bind even when the first harvest had no `evidence_id` and other MACs exist. A DC-scoped dump does not donate its MACs to the victim. Same-line talking-IP donate and omitted-key persist stay.
