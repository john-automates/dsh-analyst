# Agent Note: Persist unnamed extra-wan dests on c2_ips

Status: implemented

English | [中文](2026-08-21-persist-unnamed-extra-wan-c2-dests.zh.md)

## Problem

After [unique-collapse extra-wan](2026-08-21-unique-collapse-extra-wan-before-clip.md), extra-wan can harvest unnamed victim-stamped WAN dests. [Persist attested C2 dests](2026-08-21-persist-attested-c2-dests.md) keeps only the bound C2 (when it is not CDN/CF) plus dests that evidence the accepted non-CDN `c2_domain`. An unnamed extra-wan dest that survives CDN/update hostname omit and Cloudflare IPv4 omit still drops from `c2_ips`. Who/where stay victim-only; the harvested extras are missing.

Shrinking persist to the bound C2 first would still drop those dests. Retuning `acceptedC2Domain` would not put an unnamed dest on `c2_ips`.

## Decision

`acceptedC2Ips` is the attested extra-wan set: the bound C2 when it is not CDN/CF, plus victim-stamped extra-wan dests that survive `ipIsCdnOrUpdate` (evidenced CDN/update hostname or published Cloudflare or Fastly IPv4). An unnamed dest that survives those omits persists. A dest that `isCdnOrUpdateName`, `isCloudflareIpv4`, or `isFastlyIpv4` would omit still drops.

`acceptedC2Domain` still chooses the first dotted `isC2DomainName` that is not CDN/update, evidenced on that attested set. Who/where stay the victim row. A second bind is not invented.

[Persist attested C2 dests](2026-08-21-persist-attested-c2-dests.md) still owns domain choice from attested extras and not shrinking persist to the bound C2 first. Unique-collapse clip, refuse-complete, identity leftover, authenticatoor.org selection, CDN/CF suffix and prefix lists, Mission/Plan gates, and live-case gold IPs stay out of this change. Tests use a synthetic LAN client, TEST-NET C2 `198.51.100.80`, unnamed extras `203.0.113.50` / `203.0.113.60`, CDN dest `203.0.113.80` with `update.microsoft.com`, and Cloudflare-range fixture `104.16.1.1`.

## Alternatives considered

**Keep persist as bound C2 plus dests that evidence the accepted domain.** Rejected: unnamed extra-wan dests that survive CDN/CF omit still drop.

**Persist every harvested WAN dest, including CDN/CF.** Rejected: CDN/update hostname omit and Cloudflare IPv4 omit stay.

**Retune `acceptedC2Domain` or add an akamaized.net / authenticatoor.org pick.** Rejected: domain selection is a separate leftover.

**Bake a 45.125 dest into harness code or tests.** Rejected: tests use TEST-NET extras.

**Retune unique-collapse clip, `maxOutputChars`, or refuse-complete.** Rejected: those knobs already hit.

**Retouch identity leftover or who/where.** Rejected: who/where stay victim-only.

**Teach only the methodology prompt.** Rejected: leftover extras would still drop unnamed dests.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` persists unnamed extras `203.0.113.50` and `203.0.113.60` with or without an accepted domain, still omits `update.microsoft.com` dest `203.0.113.80` and Cloudflare dest `104.16.1.1`, and keeps `acceptedC2Domain` on `payload.example.test` when that name is evidenced on a surviving dest. Who/where hostname stays `lan-host`. `investigation.spec.ts` leftover extras include the unnamed dest and still omit the CDN dest. Existing microsoft / msn / bing / sfx / akamai / Cloudflare omit stays.

## Consequences

Unnamed non-CDN extra-wan dests land on `c2_ips`. A dest with a CDN/update hostname, or a Cloudflare or Fastly IPv4, still drops. Domain selection is unchanged. Who/where stay the victim row.
