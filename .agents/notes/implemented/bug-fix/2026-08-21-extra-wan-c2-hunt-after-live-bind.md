# Agent Note: Extra-WAN C2 hunt after live bind

Status: implemented

English | [中文](2026-08-21-extra-wan-c2-hunt-after-live-bind.zh.md)

## Problem

After a live bind the chassis only treats the unique bound C2 as a C2. Other WAN conversations from the victim IP are not hunted or persisted. The existing [`c2-domain`](2026-08-21-c2-domain-hunt-after-live-bind.md) hunt (TLS SNI + DNS) runs only for that one bound C2, and `CaseReport.c2_domain` stays empty when the dotted name is evidenced on another WAN peer or is harvested after bind without `evidence_id` of the bound C2.

`acceptedC2Domain` keys only `boundC2Ipv4`. Nothing issues `ip.src ==` the victim looking for other non-LAN unicast destinations. Extra C2 IPs never appear on the accepted packet. Donating those IPs or names onto who/where would invert the victim row.

## Decision

A successful `bind_relationship` with a unique LAN victim and unique non-LAN C2 issues an `extra-wan` hunt whose subject is that victim IPv4. The filter is `ip.src ==` the victim talking to a non-LAN unicast destination that is not the already-bound C2 (RFC1918, loopback, link-local, multicast, reserved, and `0.0.0.0` stay out). The field is `ip.dst`. A both-LAN or CDN/update C2 deny never reaches a live bind, so this hunt is not issued ([refuse both-LAN bind](2026-08-21-refuse-both-lan-bind.md), [refuse CDN/update C2](2026-08-21-refuse-cdn-update-c2.md)).

When `autoHunt` is true, `extra-wan` auto-runs through `pcap_filter` even though the subject is the LAN victim and even when a C2-talking focus IP exists, only after Plan is ready (cue `valid` or `open`, a C2 hypothesis, a CDN/DC/update alternative, and an inventory). Mission does not unlock that auto-run ([persist leftover C2 extras without a 5W1H close](2026-08-21-persist-c2-extras-without-close.md)). `scopeIpFromHunt` returns that victim so harvest stamps dest `kind=ip` with `evidence_id` of the victim. The plugin then issues [`c2-domain`](2026-08-21-c2-domain-hunt-after-live-bind.md) for each C2 IPv4 (bound plus extras). `shouldAutoRunHunt` still allows `c2-domain` on non-LAN subjects.

`acceptedC2Ips` is the unique bound C2 first, then non-LAN unicast IPs whose `evidence_id` is that victim. CDN / DNS / update IPs harvested from earlier dumps with no stamp or a non-victim stamp stay off. An IP whose evidenced hostname is a well-known CDN or update name is also omitted, bound C2 included ([refuse CDN/update C2](2026-08-21-refuse-cdn-update-c2.md)). The Report hook copies those remaining IPv4s onto `investigation/extras` even when prose `case_report` stays unbound, and onto optional `c2_ips` on an accepted packet. `acceptedC2Domain` / `projectCaseReport` look at hostname identities evidenced on any of those remaining IPs, still gated by `isC2DomainName`, skip CDN/update names, and persist the first remaining dotted name as `c2_domain`. Who/where stay the victim row. Extra C2s are not donated onto who/where hostname or ip. A second bind is not invented. LAN / DC / gateway / multicast / unbound WAN / `DESKTOP-*` stay off.

Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, extra WAN `203.0.113.50`, distractor WAN `203.0.113.99`, idle/DC LAN peer, and `c2.example.test`.

## Alternatives considered

**Wait for the model to hunt other WAN peers after bind.** Rejected: extra C2s never appear because nothing hunts victim→other-WAN after bind.

**Treat extra WAN destinations as a second bind.** Rejected: who/where stay victim-only. Extra C2s persist on `c2_ips`, not as bind endpoints.

**Put extra C2 IPs or the C2 domain on who/where.** Rejected: that donates C2 onto the victim row.

**Issue `c2-domain` only for `boundC2Ipv4`.** Rejected: `c2_domain` stays empty when the dotted name is stamped on an extra C2.

**Block `extra-wan` when a C2-talking focus IP exists.** Rejected: the subject is the LAN victim; focus scoping would skip the hunt that finds extras.

**Take every non-LAN IP on the ledger as `c2_ips`.** Rejected: `harvestIdentities` already records every IPv4 in tool-result text. Earlier dumps leave CDN / DNS / update IPs unstamped or stamped on a non-victim; those must not persist or get `c2-domain` hunts.

**Bake gold C2 IPs or domains from a live case into harness code or tests.** Rejected: tests use TEST-NET and `c2.example.test`.

**Invent evals or touch scout.** Rejected: this knob is extra-WAN harvest after a live bind.

## Testing

`packages/analyst/investigation/tests/hunts.spec.ts` pins `extra-wan` filter, fields, notice, and auto-run on LAN `10.0.10.2` with TEST-NET C2 `198.51.100.80`. `bind.spec.ts` persists extra WAN `203.0.113.50` (`evidence_id` of the victim) on `c2_ips` with the bound C2 first, excludes unstamped or non-victim-stamped distractor WAN `203.0.113.99` plus LAN/DC/gateway, issues `c2-domain` per accepted C2 IP, persists `c2.example.test` as `c2_domain` when stamped on the extra C2, leaves who/where hostname `lan-host` and ip the victim, and issues neither hunt for a constructed LAN C2. `harvest.spec.ts` stamps a scoped dest IP. `investigation.spec.ts` issues and auto-runs `extra-wan` then per-C2 `c2-domain` after `bind_relationship` and keeps `203.0.113.99` off `c2_ips`; a both-LAN or LAN-c2 deny issues neither. `analyst-tools/tests/tools.spec.ts` closes through `case_report` and keeps identity slots unchanged.

## Consequences

A live LAN-victim / non-LAN-C2 bind can persist extra WAN C2 IPs and a dotted C2 domain evidenced on any of those IPs without a model SNI, DNS, or extra-peer call. who/where stay the victim row. A missing harvest omits `c2_domain`. A both-LAN refuse still issues no C2 hunt.
