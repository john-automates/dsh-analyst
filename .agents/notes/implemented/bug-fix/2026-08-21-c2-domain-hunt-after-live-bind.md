# Agent Note: C2-domain hunt after live bind

Status: implemented

English | [中文](2026-08-21-c2-domain-hunt-after-live-bind.zh.md)

## Problem

Identity close can land 5/5 with correct LAN-victim / non-LAN-C2 orientation while the C2 domain extra still fails. The model never queries TLS SNI or DNS for the bound C2 IP, so that name never enters the session or the accepted report.

`huntsToAutoRun` does not run a hunt whose subject is a non-LAN / C2 IP, except [`other-end`](2026-08-21-other-end-hunt-on-cue-victim.md). There is no hunt kind for TLS SNI / DNS on the bound C2. `CaseReport` holds who/what/when/where/why/how only; nothing persists a C2 domain onto the accepted packet. Mutating who/where hostname would donate a C2 name onto the victim row.

## Decision

A successful `bind_relationship` with a unique non-LAN `c2` IPv4 issues a `c2-domain` hunt whose subject is that C2, and [extra-WAN](2026-08-21-extra-wan-c2-hunt-after-live-bind.md) then issues the same hunt for each harvested extra WAN IPv4. The filter is `tls.handshake.extensions_server_name or dns.qry.name or dns.resp.name` scoped with `ip.addr ==` that C2. Those three names are valid tshark 4.4.16 fields. A both-LAN deny never reaches a live bind, so this hunt is not issued for a LAN C2 ([refuse both-LAN bind](2026-08-21-refuse-both-lan-bind.md)).

When `autoHunt` is true, `c2-domain` auto-runs through `pcap_filter` like `other-end`, even though its subject is the C2. [Identity-hunt auto-run](2026-08-21-auto-run-outstanding-identity-hunts.md) still skips non-LAN subjects for `eth-src`, `name-service`, Kerberos, and SAMR.

Harvest records the SNI or DNS name as hostname with `evidence_id` of that C2 IP. Workgroup and NBNS tokens stay rejected as today. Under a non-LAN C2 `scopeIp`, single-label LAN / DC / NetBIOS names are not recorded. That hostname does not donate who/where ([BindRelationship](../feature/2026-08-21-bind-relationship.md)). The accepted `case_report` copies the first dotted DNS name evidenced on any of those C2 IPv4s (bound plus extras) onto optional `c2_domain`. The field is omitted when none was harvested. A domain is not invented.

Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, idle/DC LAN peer, and `c2.example.test`.

## Alternatives considered

**Wait for the model to query TLS SNI or DNS.** Rejected: the C2 domain extra failed with zero session hits after a correct bind.

**Put the C2 name on who/where hostname.** Rejected: that donates a C2 domain onto the victim row.

**Auto-run every hunt whose subject is the C2 IP.** Rejected: that would persist far-side NIC and LAN name-service rows. The exception is `c2-domain` only, beside `other-end`.

**Invent a domain, or bake gold C2 names into harness code or tests.** Rejected: persist only a harvested dotted DNS name. Tests use `c2.example.test`, not live-case values.

**Issue `c2-domain` from `huntsForNewIdentities` when the C2 IP is harvested.** Rejected: the hunt is scoped to a live bind's C2 role, not every non-LAN IP.

**Invent evals or touch scout.** Rejected: this knob is C2-domain harvest after a live bind.

## Testing

`packages/analyst/investigation/tests/hunts.spec.ts` pins `c2-domain` filter, fields, notice, and auto-run on TEST-NET `198.51.100.80`. `harvest.spec.ts` harvests `tls.handshake.extensions_server_name` / `dns.qry.name` as hostname with `evidence_id` of that C2 and keeps `lan-host` / `dc01` / workgroup off that scope. `bind.spec.ts` persists `c2.example.test` as `c2_domain`, leaves who/where hostname `lan-host`, and issues no hunt for a constructed LAN C2. `investigation.spec.ts` issues and auto-runs the hunt after `bind_relationship`, and a both-LAN or LAN-c2 deny issues none. `analyst-tools/tests/tools.spec.ts` closes through `case_report` and keeps identity slots unchanged.

## Consequences

A live LAN-victim / non-LAN-C2 bind can persist the evidenced C2 domain without a model SNI or DNS call. who/where stay the victim row. A missing harvest omits `c2_domain`. A both-LAN refuse still issues no C2 hunt.
