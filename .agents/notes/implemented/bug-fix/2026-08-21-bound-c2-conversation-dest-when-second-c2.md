# Agent Note: Bound C2 is conversation dest when a second C2 is named

Status: implemented

English | [中文](2026-08-21-bound-c2-conversation-dest-when-second-c2.zh.md)

## Problem

[`boundC2Ipv4`](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) required exactly one role `c2` IPv4. A live bind with a unique LAN victim, conversation dest role `c2`, and a second endpoint also role `c2` left `boundC2Ipv4` undefined. extra-wan never issued. Persist `c2_ips` dropped the conversation dest. The extra-wan other-WAN filter had no dest to exclude.

A unique C2 role is not required to issue extra-wan or to persist that dest. Two `c2` roles whose dest is not `c2` must not invent an IP.

## Decision

`boundC2Ipv4` is the conversation dest when that endpoint is role `c2` and a non-LAN unicast IPv4, even if another endpoint is also `c2`. Otherwise the unique role `c2` IPv4 still wins. Two `c2` roles with dest not `c2` return undefined. extra-wan still issues only for a unique LAN victim and that bound C2. Persist `acceptedC2Ips` still starts with that bound dest, subject to existing CDN/CF omit. A bind with no victim still does not issue extra-wan.

[Extra-WAN C2 hunt after live bind](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) still owns extra-wan issue, dest exclusion, and attested extras. [Persist unnamed extra-wan dests](2026-08-21-persist-unnamed-extra-wan-c2-dests.md) still owns unnamed persist and CDN/CF omit. Unique-collapse clip, refuse-complete, `acceptedC2Domain` selection, identity leftover, who/where, Plan/Mission/cue-pending, and live-case gold IPs stay out of this change. Tests use a synthetic LAN client, TEST-NET dest `198.51.100.80`, and second C2 `203.0.113.50`.

## Alternatives considered

**Keep requiring exactly one role `c2`.** Rejected: dest plus a second `c2` empties `boundC2Ipv4`, so extra-wan never issues and persist drops dest.

**Issue extra-wan from the victim with no bound C2.** Rejected: the extra-wan filter needs dest to exclude; persist would have no dest.

**Treat the first role `c2` endpoint as bound when dest is not `c2`.** Rejected: two `c2` roles without conversation dest must not invent an IP.

**Persist every role `c2` endpoint.** Rejected: this knob is dest as `boundC2Ipv4`. Victim-stamped extras stay on the attested set.

**Bake a 185.188 or 45.125 dest into harness code or tests.** Rejected: tests use TEST-NET.

**Retune persist-unnamed extra-wan, unique-collapse, refuse-complete, `acceptedC2Domain`, or identity leftover.** Rejected: those knobs stay.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` keeps dest `198.51.100.80` as `boundC2Ipv4` when extra WAN `203.0.113.50` is also `c2`, issues extra-wan for LAN `10.0.10.2`, persists dest on `c2_ips`, returns undefined when dest is `infra` and two other endpoints are `c2`, and still issues extra-wan for dest-as-infra plus one unique `c2`. `investigation.spec.ts` issues extra-wan and `c2-domain` for dest after that two-C2 bind. `analyst-tools/tests/tools.spec.ts` keeps dest on `case_report` `c2_ips`. Unique-C2, unnamed persist, and CDN/CF omit stay.

## Consequences

A live bind that names dest as `c2` plus another `c2` still hunts extra WAN dests and can persist that dest. Two `c2` roles without conversation dest invent nothing. Who/where stay the victim row.
