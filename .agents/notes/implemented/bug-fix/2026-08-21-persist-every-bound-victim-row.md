# Agent Note: Persist every bound victim row across accepted closes

Status: implemented

English | [中文](2026-08-21-persist-every-bound-victim-row.zh.md)

## Problem

A live two-client harvest bound two infected LAN workstations, then CaseReport published one victim. The later accepted bind named a different victim IPv4; that row was overwritten by or folded into the first published who/where. Chassis Mission / closed-means stay single-victim leftover (form miss). Host-without-hunts leftover and family extras are a different persist.

[Persist the projected victim row](2026-08-21-persist-projected-victim-slot.md) fills omitted keys on the live bind's row. `investigation/report` still last-wins one who/where. A later close or extras re-append replaced the earlier victim.

## Decision

After live binds, persist every bound victim row. Fold published rows by `entity_id`.

`who` / `where` stay the latest accepted close's projected victim row. `victims` holds first-seen rows when two or more distinct victim IPv4s were published. A single-bind close omits `victims`. A later accepted close or live bind that names a different victim appends. A later close of the same victim updates that row and does not invent a duplicate. `recordBind` persists that bind's completed victim row onto an already-accepted packet and does not invent 5W1H when none exists. `foldReport` reconstructs the same rows from the log. Omitted-slot fill still runs per victim from that victim's harvest, including [omitted user](2026-08-21-persist-harvested-human-on-omitted-who.md) and [AD SRV hostname skip](2026-08-21-omit-ad-srv-locator-hostname.md). Bind role infra, DC, gateway, and file-server rows are not published. Users, hostnames, and MACs are not invented.

[LAN/gateway/DC leftover coerce](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md) and [omit AD SRV locator hostname](2026-08-21-omit-ad-srv-locator-hostname.md) stay. `acceptedC2Ips` / `acceptedC2Domain` / extra-wan / Fastly / Cloudflare / CDN suffixes, Mission / Plan / cue-pending, refuse-complete, and family persist stay. Chassis form stays single-victim leftover.

Tests use synthetic RFC1918 / TEST-NET stand-ins.

## Alternatives considered

**Keep last-wins one who/where.** Rejected: a later accepted bind that names a different victim then drops the already-published row.

**Change who/where to arrays.** Rejected: one-bind Easy as 123 / fake-software closes stay one victim row on who/where.

**Invent a 5W1H packet on bind before any close.** Rejected: persist-without-close does not invent who/where.

**Retune LAN/gateway/DC leftover coerce or AD SRV hostname omit.** Rejected: this knob is persist of already-projected victim rows.

**Publish bind role infra, DC, gateway, or file-server as a victim row.** Rejected: who/where stay victim-only on each row.

**Invent a duplicate row when the same victim is re-closed.** Rejected: that close updates the existing row.

**Bake live-case gold IPs, MACs, hostnames, users, or the real AD domain into fixtures or notes.** Rejected: tests use `10.0.10.2` / `10.0.10.8`, TEST-NET C2 `198.51.100.80` / `198.51.100.81`, and DC/infra `10.0.10.3`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses synthetic victims `10.0.10.2` and `10.0.10.8`, TEST-NET C2 `198.51.100.80` / `198.51.100.81`, and DC/infra `10.0.10.3`. One bind still publishes one victim row. Two accepted closes with those distinct victim IPv4s publish two victim rows (who/where per victim, victim-only), including omitted-slot fill from each victim's harvest and AD SRV skip. A second close of the same victim updates that row. Infra stays off. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same two-bind path through `bind_relationship` then `case_report`, including persist of the second victim after the later bind before a second close.

## Consequences

Two live binds on two distinct victim IPv4s publish both victim rows. A later different victim does not replace the first published row. A single-bind close stays one row. Same-victim re-close updates that row. Infra stays off who/where.
