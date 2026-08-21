# Agent Note: Unique-collapse extra-wan dests before clip

Status: implemented

English | [中文](2026-08-21-unique-collapse-extra-wan-before-clip.zh.md)

## Problem

After a live bind, [`extra-wan`](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) hunts other WAN dests of the victim (`ip.src ==` the victim, field `ip.dst`). `pcap_filter` clips raw tshark stdout at `maxOutputChars` (default 32000), then labels rows. A victim→WAN dump with thousands of repeated dest lines exceeds that clip. Later first-seen dests stay in the pcap and match the extra-wan filter, but never become session hits. Unnamed extra-wan dests that survive CDN/CF omit persist ([persist unnamed extra-wan dests](2026-08-21-persist-unnamed-extra-wan-c2-dests.md)). Who/where stay victim-only. This knob is hunt visibility, not persist widening.

Raising `maxOutputChars` would keep per-packet repeats in history. Unique-collapsing after the clip cannot recover dests the clip already dropped.

## Decision

`pcap_filter` unique-collapses extra-wan `ip.dst` in first-seen order before the output clip. extra-wan is the only hunt whose fields are exactly `ip.dst`. Other hunts (`eth-src`, `name-service`, `kerberos-cname`, `samr-userinfo`, `other-end`, `c2-domain`) stay per-packet. The extra-wan display filter and field stay the same. `maxOutputChars` stays 32000. Clip still applies to the unique output when that unique text exceeds the cap.

Unnamed extra-wan dests can become session hits. Persist of those dests is [persist unnamed extra-wan dests](2026-08-21-persist-unnamed-extra-wan-c2-dests.md). Who/where stay the victim row. Live-case gold IPs are not listed. Tests use TEST-NET extras `203.0.113.10` and `203.0.113.99`.

## Alternatives considered

**Raise `maxOutputChars` so later per-packet dests survive.** Rejected: the useful extra-wan result is unique dests. A larger per-packet dump keeps repeats in history.

**Unique-collapse every hunt field dump.** Rejected: identity hunts and `other-end` need per-packet rows. extra-wan is the dest inventory.

**Unique-collapse after `clipOutput`.** Rejected: dests whose first occurrence is past the clip never appear.

**Bake a live-case dest into harness code or tests.** Rejected: tests use TEST-NET extras.

**Widen persist so unnamed extra-wan dests enter `c2_ips`.** Rejected: this knob is hunt visibility. Persist stays attested dests.

**Retouch identity leftover, authenticatoor.org selection, CDN/CF omit, Plan/Mission gates, or cue-pending.** Rejected: those leftovers are separate.

## Testing

`packages/analyst/analyst-tools/tests/tools.spec.ts` unique-collapses a sole `ip.dst` dump so a dest that first appears after the clip budget is labeled, keeps first-seen order, still clips unique dests that exceed the budget, and leaves an `ip.src` (`other-end`) dump per-packet so that late dest stays hidden. `packages/analyst/investigation/tests/hunts.spec.ts` pins extra-wan fields as `ip.dst` and keeps other hunts off that sole field.

## Consequences

extra-wan session hits include later first-seen WAN dests without raising the output cap. Persist of unnamed dests is [persist unnamed extra-wan dests](2026-08-21-persist-unnamed-extra-wan-c2-dests.md). Who/where stay the victim row. A unique dest list that exceeds `maxOutputChars` still clips.
