# Agent Note: Refuse CDN/update BindRelationship C2

Status: implemented

English | [中文](2026-08-21-refuse-cdn-update-c2.zh.md)

## Problem

After [extra-WAN](2026-08-21-extra-wan-c2-hunt-after-live-bind.md), a leftover-extras bind can take the first `:443` dest from a clipped 80/443 dump. That dest may be a well-known CDN or software-update peer (Akamai / Microsoft SNI), not malware C2. extra-wan then persists every victim-stamped WAN dest, including that CDN/update noise. `acceptedC2Domain` first-wins can persist a Microsoft update SNI and skip a later non-CDN dotted name on another extra IP. Who/where stay victim-only; the C2 extras are wrong.

`resolveBind` already refuses a [both-LAN conversation](2026-08-21-refuse-both-lan-bind.md) and a LAN `c2`. It accepts any unique non-LAN C2. `isC2DomainName` only requires a dotted non-IPv4 name.

## Decision

`isCdnOrUpdateName` is a suffix check on well-known public CDN and software-update domains: `microsoft.com`, `windows.com`, `windowsupdate.com`, `office.com`, `live.com`, `msn.com`, `bing.com`, `microsoftonline.com`, `sfx.ms`, `akamai.net`, `akamaiedge.net`, `akamaihd.net`, `akamaized.net`, `akadns.net`, `edgesuite.net`, `edgekey.net`, `cloudflare.com`, `cloudfront.net`, `fastly.net`. The registrable suffix and its subdomains match (`update.microsoft.com`, `windows.msn.com`, `www.bing.com`, `login.microsoftonline.com`, `sfx.ms`, `a1.akamai.net`, `img-s-msn-com.akamaized.net`). IPv4 ranges are not this name test; published Cloudflare prefixes are a sibling omit ([omit Cloudflare IPv4 C2 dests](2026-08-21-omit-cloudflare-ipv4-c2-dests.md)). Live-case gold names are not listed. `isC2DomainName` stays; this check is additional.

`resolveBind` takes optional folded identities and tool-result text. After the existing request checks, a unique non-LAN C2 with an evidenced CDN/update hostname is unbound. Evidence is a harvested hostname whose `evidence_id` is that C2 IPv4, or a cited-conversation TLS SNI, HTTP host, or DNS name on a line that names that IP. The deny text is `unbound: role c2 cannot be a well-known CDN or update destination.` A replacement C2 is not invented. The bind is not recorded. extra-wan and c2-domain are not issued, the same as both-LAN.

`acceptedC2Ips` omits an IP — bound C2 included — whose evidenced hostname is CDN/update, or whose IPv4 is a published Cloudflare dest. Persist is the attested extra-wan set, including unnamed dests that survive those omits ([persist unnamed extra-wan dests](2026-08-21-persist-unnamed-extra-wan-c2-dests.md)). `acceptedC2Domain` / `projectCaseReport` persist the first dotted `isC2DomainName` that is not CDN/update, evidenced on an attested dest. CDN/update names and hostnames evidenced only on a dropped Cloudflare dest never win. Who/where stay the victim row.

[BindRelationship](../feature/2026-08-21-bind-relationship.md) still owns bind-before-close. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, CDN dest `203.0.113.80` with `update.microsoft.com` or `a1.akamai.net`, msn dest `203.0.113.81` with `windows.msn.com`, bing dest `203.0.113.84` with `www.bing.com`, microsoftonline dest `203.0.113.85` with `login.microsoftonline.com`, sfx dest `203.0.113.86` with `sfx.ms`, akamaized dest `203.0.113.87` with `img-s-msn-com.akamaized.net`, Cloudflare-range fixture `104.16.1.1` with `cdn-customer.example.test`, extra WAN `203.0.113.50` with `payload.example.test`, unnamed extra `203.0.113.60`, and LAN DC.

## Alternatives considered

**Accept the first non-LAN `:443` dest and let extra-wan stamp every victim→WAN peer.** Rejected: a CDN/update peer becomes the bound C2 and its SNI can win `c2_domain`.

**Invent a replacement C2 when the unique dest is CDN/update.** Rejected: tokens are not swapped and a C2 is not invented. Refuse the bind.

**Key every CDN omit off IPv4 ranges.** Rejected for Microsoft, Akamai, and software-update dests: those anycast ranges move and the hostname suffix is the evidence. Published Cloudflare prefixes are a sibling omit ([omit Cloudflare IPv4 C2 dests](2026-08-21-omit-cloudflare-ipv4-c2-dests.md)).

**Bake live-case gold IPs or hostnames into harness code or tests.** Rejected: tests use TEST-NET, `update.microsoft.com`, `windows.msn.com`, `www.bing.com`, `login.microsoftonline.com`, `sfx.ms`, `a1.akamai.net`, `img-s-msn-com.akamaized.net`, `104.16.1.1`, `cdn-customer.example.test`, and `payload.example.test`.

**Fold CDN/update into `isC2DomainName` so those names are not harvested.** Rejected: harvest must still record the name so bind and persist can refuse it.

**Teach only the methodology prompt or the tool description.** Rejected: a leftover-extras bind would still accept the CDN dest.

**Invent evals or touch scout.** Rejected: this knob is CDN/update refuse on bind and leftover extras.

## Testing

`packages/analyst/investigation/tests/harvest.spec.ts` pins `isCdnOrUpdateName` on the listed suffixes and subdomains, including `windows.msn.com`, `www.bing.com`, `login.microsoftonline.com`, `sfx.ms`, and `img-s-msn-com.akamaized.net`, and keeps `payload.example.test` / `evilmicrosoft.com` / `evilmsn.com` / `evilbing.com` / `bing.com.evil.test` / `evilakamaized.net` / `akamaized.net.evil.test` / `evilcloudflare.com` off. `bind.spec.ts` denies `10.0.10.2` ↔ `203.0.113.80` when `update.microsoft.com` or `a1.akamai.net` is evidenced on that dest (identity or cited-conversation SNI / HTTP host) and does not issue a hunt; it also denies `10.0.10.2` ↔ `203.0.113.81` when `windows.msn.com` is evidenced, `10.0.10.2` ↔ `203.0.113.84` / `203.0.113.85` / `203.0.113.86` when `www.bing.com`, `login.microsoftonline.com`, or `sfx.ms` is evidenced, and `10.0.10.2` ↔ `203.0.113.87` when `img-s-msn-com.akamaized.net` is evidenced. `10.0.10.2` ↔ `198.51.100.80` with `payload.example.test` still accepts. `acceptedC2Ips` drops victim-stamped dests whose hostname is `update.microsoft.com`, `windows.msn.com`, `www.bing.com`, `login.microsoftonline.com`, `sfx.ms`, `a1.akamai.net`, or `img-s-msn-com.akamaized.net`, plus published Cloudflare dest `104.16.1.1` even when the hostname is `cdn-customer.example.test`, and keeps extra WAN `203.0.113.50` when `payload.example.test` is evidenced on that dest, unnamed extra `203.0.113.60`, plus the bound C2 that has no CDN name and no Cloudflare IP. Unnamed extra persist is [persist unnamed extra-wan dests](2026-08-21-persist-unnamed-extra-wan-c2-dests.md). `acceptedC2Domain` skips those CDN/update names, including first-seen `windows.msn.com` or `www.bing.com` or `img-s-msn-com.akamaized.net` or `cdn-customer.example.test`, and persists later `payload.example.test` from a remaining C2 IP. Who/where hostname stays `lan-host`. Both-LAN and LAN-C2 denies stay unchanged. `investigation.spec.ts` denies the CDN bind through `tools.execute` without recording extra-wan or c2-domain, accepts the payload C2, and persists leftover extras without the CDN dest.

## Consequences

A unique C2 whose evidenced name is a well-known CDN or update dest stays unbound and issues no C2 hunt. After a live bind, leftover extras omit those dests from `c2_ips` and never let those names win `c2_domain`. Who/where stay the victim row. A missing harvest omits `c2_domain`.
