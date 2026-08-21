# Agent Note: Refuse CDN/update BindRelationship C2

Status: implemented

English | [中文](2026-08-21-refuse-cdn-update-c2.zh.md)

## Problem

After [extra-WAN](2026-08-21-extra-wan-c2-hunt-after-live-bind.md), a leftover-extras bind can take the first `:443` dest from a clipped 80/443 dump. That dest may be a well-known CDN or software-update peer (Akamai / Microsoft SNI), not malware C2. extra-wan then persists every victim-stamped WAN dest, including that CDN/update noise. `acceptedC2Domain` first-wins can persist a Microsoft update SNI and skip a later non-CDN dotted name on another extra IP. Who/where stay victim-only; the C2 extras are wrong.

`resolveBind` already refuses a [both-LAN conversation](2026-08-21-refuse-both-lan-bind.md) and a LAN `c2`. It accepts any unique non-LAN C2. `isC2DomainName` only requires a dotted non-IPv4 name.

## Decision

`isCdnOrUpdateName` is a suffix check on well-known public CDN and software-update domains: `microsoft.com`, `windows.com`, `windowsupdate.com`, `office.com`, `live.com`, `akamai.net`, `akamaiedge.net`, `akamaihd.net`, `akadns.net`, `edgesuite.net`, `edgekey.net`, `cloudflare.com`, `cloudfront.net`, `fastly.net`. The registrable suffix and its subdomains match (`update.microsoft.com`, `a1.akamai.net`). IPv4 ranges are not this test. Live-case gold names are not listed. `isC2DomainName` stays; this check is additional.

`resolveBind` takes optional folded identities and tool-result text. After the existing request checks, a unique non-LAN C2 with an evidenced CDN/update hostname is unbound. Evidence is a harvested hostname whose `evidence_id` is that C2 IPv4, or a cited-conversation TLS SNI, HTTP host, or DNS name on a line that names that IP. The deny text is `unbound: role c2 cannot be a well-known CDN or update destination.` A replacement C2 is not invented. The bind is not recorded. extra-wan and c2-domain are not issued, the same as both-LAN.

`acceptedC2Ips` omits an IP — bound C2 included — whose evidenced hostname is CDN/update. Victim-stamped extras that are not CDN/update still persist. `acceptedC2Domain` / `projectCaseReport` persist the first dotted `isC2DomainName` that is not CDN/update, evidenced on any remaining C2 IP. CDN/update names never win. Who/where stay the victim row.

[BindRelationship](../feature/2026-08-21-bind-relationship.md) still owns bind-before-close. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, CDN dest `203.0.113.80` with `update.microsoft.com` or `a1.akamai.net`, extra WAN `203.0.113.50` with `payload.example.test`, and LAN DC.

## Alternatives considered

**Accept the first non-LAN `:443` dest and let extra-wan stamp every victim→WAN peer.** Rejected: a CDN/update peer becomes the bound C2 and its SNI can win `c2_domain`.

**Invent a replacement C2 when the unique dest is CDN/update.** Rejected: tokens are not swapped and a C2 is not invented. Refuse the bind.

**Key the classifier off IPv4 ranges.** Rejected: CDN and update anycast ranges move. The hostname suffix is the evidence.

**Bake live-case gold IPs or hostnames into harness code or tests.** Rejected: tests use TEST-NET, `update.microsoft.com`, `a1.akamai.net`, and `payload.example.test`.

**Fold CDN/update into `isC2DomainName` so those names are not harvested.** Rejected: harvest must still record the name so bind and persist can refuse it.

**Teach only the methodology prompt or the tool description.** Rejected: a leftover-extras bind would still accept the CDN dest.

**Invent evals or touch scout.** Rejected: this knob is CDN/update refuse on bind and leftover extras.

## Testing

`packages/analyst/investigation/tests/harvest.spec.ts` pins `isCdnOrUpdateName` on the listed suffixes and subdomains and keeps `payload.example.test` / `evilmicrosoft.com` off. `bind.spec.ts` denies `10.0.10.2` ↔ `203.0.113.80` when `update.microsoft.com` or `a1.akamai.net` is evidenced on that dest (identity or cited-conversation SNI / HTTP host) and does not issue a hunt; `10.0.10.2` ↔ `198.51.100.80` with `payload.example.test` still accepts. `acceptedC2Ips` drops victim-stamped `203.0.113.80` whose hostname is `update.microsoft.com` and keeps extra WAN `203.0.113.50`. `acceptedC2Domain` skips that Microsoft name and persists `payload.example.test` from the other C2 IP. Who/where hostname stays `lan-host`. Both-LAN and LAN-C2 denies stay unchanged. `investigation.spec.ts` denies the CDN bind through `tools.execute` without recording extra-wan or c2-domain, accepts the payload C2, and persists leftover extras without the CDN dest.

## Consequences

A unique C2 whose evidenced name is a well-known CDN or update dest stays unbound and issues no C2 hunt. After a live bind, leftover extras omit those dests from `c2_ips` and never let those names win `c2_domain`. Who/where stay the victim row. A missing harvest omits `c2_domain`.
