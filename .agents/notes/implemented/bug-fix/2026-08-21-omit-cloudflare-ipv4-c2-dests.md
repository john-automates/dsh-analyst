# Agent Note: Omit Cloudflare IPv4 dests from accepted C2 persist

Status: implemented

English | [中文](2026-08-21-omit-cloudflare-ipv4-c2-dests.zh.md)

## Problem

After [hostname-suffix CDN/update omit](2026-08-21-refuse-cdn-update-c2.md), a leftover extra dest in a published Cloudflare IPv4 prefix can still persist. The evidenced hostname on that dest is often a customer domain, not `cloudflare.com`, so `isCdnOrUpdateName` is false. `acceptedC2Ips` keeps the dest. `acceptedC2Domain` first-wins that customer name and skips a later dotted name evidenced on a remaining non-CDN dest. Who/where stay victim-only; the C2 extras are wrong.

Adding another one-off hostname suffix does not fix the next customer name on the same anycast dest.

## Decision

`isCloudflareIpv4` matches the published Cloudflare IPv4 anycast prefixes ([Cloudflare IP ranges](https://www.cloudflare.com/ips/)), including `104.16.0.0/13`. A dest in those ranges is CDN even when the evidenced hostname is a customer domain. Generic VPS / hosting ranges are not this check. Live-case gold IPs are not listed. `isCdnOrUpdateName` stays suffix-only; `evilcloudflare.com` stays false.

`acceptedC2Ips` omits a published Cloudflare dest — bound C2 included — the same way it omits a dest whose evidenced hostname is CDN/update. Persist is the bound C2 (when it is not CDN/CF) plus dests that evidence the accepted non-CDN `c2_domain`; a leftover unnamed extra does not persist ([persist attested C2 dests](2026-08-21-persist-attested-c2-dests.md)). `acceptedC2Domain` / `projectCaseReport` persist the first dotted `isC2DomainName` that is not CDN/update, evidenced on an attested dest. A hostname evidenced only on a dropped Cloudflare dest does not win. Who/where stay the victim row.

`resolveBind` treats a unique non-LAN C2 in a published Cloudflare prefix as unbound, with the same deny text as a CDN/update hostname. A replacement C2 is not invented. extra-wan and c2-domain are not issued.

[Refuse CDN/update C2](2026-08-21-refuse-cdn-update-c2.md) still owns the hostname-suffix list. Scout, leftover-report bans, identity leftover, Mission/Plan gates, and 45.125 clipping stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, Cloudflare-range fixture `104.16.1.1` with `cdn-customer.example.test`, extra WAN `203.0.113.50` with `payload.example.test`, and LAN DC.

## Alternatives considered

**Add another one-off hostname suffix for the customer domain.** Rejected: the next leftover on the same Cloudflare dest uses a different customer name.

**Treat every VPS / generic-hosting dest as CDN.** Rejected: a non-Cloudflare extra WAN dest must still persist its dotted name.

**Key every CDN omit off IPv4 ranges.** Rejected for Microsoft, Akamai, and software-update dests: those anycast ranges move and the hostname suffix is the evidence. Published Cloudflare prefixes are the exception because a customer hostname on those dests is not `cloudflare.com`.

**Bake live-case gold IPs or hostnames into harness code or tests.** Rejected: tests use TEST-NET, `104.16.1.1`, `cdn-customer.example.test`, and `payload.example.test`.

**Fold identity leftover, auto-close, Mission/Plan gates, or 45.125 clipping into this persist knob.** Rejected: those leftovers are separate.

**Teach only the methodology prompt.** Rejected: leftover extras would still persist the Cloudflare dest.

## Testing

`packages/analyst/investigation/tests/harvest.spec.ts` pins `isCloudflareIpv4` on `104.16.1.1` / `104.16.0.0` / `104.23.255.255` / `172.64.0.1` and keeps TEST-NET, `203.0.113.50`, `104.15.255.255`, and `cdn-customer.example.test` off. `isCdnOrUpdateName('evilcloudflare.com')` and `isCdnOrUpdateName('cdn-customer.example.test')` stay false. `bind.spec.ts` denies `10.0.10.2` ↔ `104.16.1.1` with or without `cdn-customer.example.test` evidenced on that dest, drops that dest from `acceptedC2Ips`, and persists later `payload.example.test` from remaining C2 `198.51.100.80` or extra WAN `203.0.113.50`. Who/where hostname stays `lan-host`. Existing microsoft / msn / bing / sfx / akamai name omit stays.

## Consequences

A dest in a published Cloudflare IPv4 prefix drops from `c2_ips` even when its hostname is a customer domain. A hostname evidenced only on that dest does not win `c2_domain`. A later (or earlier) dotted name evidenced on a remaining non-CDN dest persists. Bound C2 with no CDN name and no Cloudflare IP stays. Who/where stay the victim row.
