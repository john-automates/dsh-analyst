# Agent Note: Persist only attested C2 dests on c2_ips

Status: implemented

English | [中文](2026-08-21-persist-attested-c2-dests.zh.md)

## Problem

After [extra-WAN](2026-08-21-extra-wan-c2-hunt-after-live-bind.md), [CDN/update omit](2026-08-21-refuse-cdn-update-c2.md), and [Cloudflare IPv4 omit](2026-08-21-omit-cloudflare-ipv4-c2-dests.md), leftover extras persist every victim-stamped non-LAN dest that is not CDN/CF. An extra-wan harvest IP with no hostname survives those omits. `c2_ips` then lists unnamed leftover WAN dests beside the bound C2 and the dest that evidences the accepted domain. Who/where stay victim-only; the C2 extras are wrong.

Shrinking persist to the bound C2 first would drop the dest that evidences the accepted non-CDN dotted name, and `c2_domain` would regress.

## Decision

`acceptedC2Domain` still chooses the first dotted `isC2DomainName` that is not CDN/update, evidenced on an attested extra: the bound C2 plus victim-stamped WAN dests that are not a published Cloudflare dest and have no well-known CDN or update hostname. extra-wan and `c2-domain` still hunt that attested set.

Persist `acceptedC2Ips` is the bound C2 when it is not CDN/CF, plus dests that evidence that accepted domain. A leftover victim-stamped WAN dest with no such attestation does not persist. Who/where stay the victim row. A second bind is not invented.

Identity leftover, how the accepted C2-domain dest is chosen, Cloudflare prefixes, the CDN/update suffix list, Mission/Plan gates, auto-close, and 45.125 clipping stay out of this change. Tests use a synthetic LAN client, TEST-NET C2 `198.51.100.80`, extra WAN `203.0.113.50` with `payload.example.test` or `c2.example.test`, unnamed extra `203.0.113.60`, CDN dest `203.0.113.80`, and Cloudflare-range fixture `104.16.1.1`. Live-case gold names and IPs are not listed.

## Alternatives considered

**Shrink persist to the bound C2 first, then choose `c2_domain` from that set.** Rejected: the dest that evidences the accepted dotted name can disappear and `c2_domain` regresses.

**Keep every victim-stamped non-CDN extra on `c2_ips`.** Rejected: unnamed leftover extras persist.

**Bake live-case gold names or IPs into harness code or tests.** Rejected: tests use TEST-NET, `payload.example.test`, and `c2.example.test`.

**Retune Cloudflare prefixes or the CDN/update suffix list.** Rejected: unnamed extras have no hostname and are not in those prefixes.

**Auto-close identity, retouch leftover identity persist, or change Mission/Plan gates.** Rejected: those leftovers are separate.

**Fix 45.125 leftover clip in the same persist.** Rejected: that miss is a separate leftover.

**Teach only the methodology prompt.** Rejected: leftover extras would still persist unnamed dests.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` persists bound C2 `198.51.100.80` plus extra WAN `203.0.113.50` when `payload.example.test` or `c2.example.test` is evidenced on that dest, drops unnamed extra `203.0.113.60`, and still omits microsoft / msn / bing / sfx / akamai / Cloudflare dests. `acceptedC2Domain` still prefers `payload.example.test` over a CDN name. Who/where hostname stays `lan-host`. extra-wan and `c2-domain` hunts still issue for attested extras, including an unnamed dest that does not persist.

## Consequences

`c2_ips` holds the bound C2 and dests that evidence the accepted non-CDN domain. Unnamed leftover extras drop. A dotted name evidenced on an attested dest still wins `c2_domain`. Who/where stay the victim row.
