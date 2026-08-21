# Agent Note: Omit AD SRV / DC locator names from victim hostname persist

Status: implemented

English | [中文](2026-08-21-omit-ad-srv-locator-hostname.zh.md)

## Problem

Live fake-r27 bound the cited conversation correctly (LAN victim / non-LAN C2) and accepted `case_report`. Identity leftover 3/4: IP / MAC / user HIT. Hostname leftover: chassis published an AD SRV / DC locator name (`_ldap._tcp…._sites.dc._msdcs.…`) over a submitted workstation hostname.

[Victim-IP-scoped donate](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) affiliates every hostname whose hunt-subject `evidence_id` is the bound victim IP. A victim-scoped name-service dump therefore donates an AD SRV query harvested on that IP. `projectVictimSlot` first-on-kind then copies that locator as hostname. [Persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md) copies donated projection keys before [keep submitted](2026-08-21-keep-submitted-victim-row-identities.md), so a submitted workstation hostname loses to the donated locator. [LAN/gateway/DC leftovers](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md) stay idle when who/where arrive as JSON objects.

## Decision

After a live bind, who/where hostname is never an AD SRV / DC locator name (`_ldap._tcp…`, `_msdcs.`, `_sites.dc.`, `_service._tcp` / `_udp`).

`projectVictimSlot` first-on-kind skips those locators the same way it skips a machine SAM for user. `completeAcceptedSlot` treats a donated locator as no donate so a submitted workstation hostname is kept. Omitted hostname persists the unique harvested workstation hostname (locators ignored). Hostname stays omitted when only that locator is harvested. A submitted locator stays off and does not fall through to that harvest. Who/where stay victim-only. A workstation hostname is not invented.

Uniqueness donate still counts every unaffiliated hostname, including locators. [LAN/gateway/DC leftovers](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md), [persist harvested human on omitted who](2026-08-21-persist-harvested-human-on-omitted-who.md), authenticatoor / `acceptedC2Domain` / `acceptedC2Ips`, extra-wan, Fastly / Cloudflare / CDN suffixes, Mission / Plan / cue-pending, and refuse-complete stay. Harvest still records locator names on the ledger. Cue-as-victim stays refused.

## Alternatives considered

**Keep first-on-kind hostname donate and let a donated locator overwrite a submitted workstation name.** Rejected: a victim-scoped name-service dump then publishes the AD SRV as who/where hostname after a correct bind.

**Retune LAN / gateway / DC leftover wrappers so a JSON victim-row close drops the locator.** Rejected: this knob is persist selection after deny/coerce. The live miss arrived as JSON objects, not leftover free text.

**Change uniqueness donate so a workstation hostname wins when locators also exist.** Rejected: this knob is persist on the accepted packet. Affiliation and donate stay. A submitted locator must still stay off rather than lose to a donated workstation.

**Drop AD SRV names at harvest.** Rejected: hostname first-on-entity lives in persist. Ledger harvest of locator queries stays.

**Persist the AD SRV / DC locator as victim hostname when no workstation name exists.** Rejected: a locator is not a workstation hostname.

**Invent a workstation hostname when only the locator is harvested.** Rejected: slots are not invented.

**Bake live-case hostnames, IPs, or the real AD domain into harness code or tests, invent evals, or retune extra-wan / authenticatoor / Fastly.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, workstation `desktop-test01` / `lan-host`, and AD SRV `_ldap._tcp.default-first-site-name._sites.dc._msdcs.ad.example.lan`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), workstation `desktop-test01` / `lan-host`, and AD SRV `_ldap._tcp.default-first-site-name._sites.dc._msdcs.ad.example.lan`. After a live bind, a ledger that donates that SRV first plus the workstation persists the workstation on who/where, including a JSON where that submits the workstation while who omits hostname. Omitted hostname persists the unique harvested workstation when uniqueness donate left the row empty because the SRV also exists. A case that harvests only the SRV leaves hostname omitted and does not invent a workstation name. A submitted SRV stays off. Cue-as-victim stays refused. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same submitted-workstation and locator-only closes through `bind_relationship` then `case_report`.

## Consequences

A live bind plus a submitted or harvested workstation hostname writes that name onto who/where even when an AD SRV / DC locator also donated. The locator never persists as victim hostname. Hostname stays omitted when only the locator is harvested. Uniqueness donate, leftover coerce, omitted user, and cue-as-victim stay.
