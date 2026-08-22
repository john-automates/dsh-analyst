# Agent Note: Refuse complete while a harvested LAN workstation is unbound

Status: implemented

English | [中文](2026-08-21-refuse-complete-while-unbound-workstation.zh.md)

## Problem

Headless can treat a text-only model stop (`finish` kind=`stop`) as `turn/end` reason `completed` and exit 0. After a live bind of one LAN victim, another harvested LAN workstation (IP plus hostname and/or human user and/or a non-infra MAC) can remain unbound. The model dismissed that host as connectivity-check noise. It was never `bind_relationship`'d and never submitted as who/where.

[Refuse complete while cue-pending or Plan not ready](2026-08-21-refuse-complete-while-cue-pending.md) already steers on `agent/turn-stopping` when Mission is cue-pending or `planReady` is false. After a named cue and ready Plan, that check allows complete. [Persist every bound victim row](2026-08-21-persist-every-bound-victim-row.md) only writes a second victim after a second live bind, so it stays idle when the leftover is never bound.

## Decision

`completeDenyReason` still names cue-pending or Plan-not-ready first. After `planReady` and at least one live bind, it also denies a text-only stop while another harvested LAN workstation remains unbound. The denial names that leftover. `agent/turn-stopping` steers that text. `turn/end` `completed` is not appended. Headless does not exit 0 from that text-only stop.

A harvested LAN workstation is a non-infra LAN IPv4 that already has workstation identity on the ledger: a non-infra hostname, a human user / `full_name`, and/or a MAC that talking-IP frames or a stamp do not source only from known infra. Bound victim IPv4s across every recorded bind are excluded. Bind role `infra`, an AD SRV / DC locator hostname on that IP, and a LAN DC / file-server / gateway role hostname on that IP are infra leftovers, not workstations ([omit LAN infra role hostnames](2026-08-22-omit-lan-infra-role-hostnames-from-leftover.md)). Once every such leftover is bound as victim, or none exists, this check allows complete again.

This check does not invent a bind, does not invent 5W1H, and does not persist an unbound host onto who/where/`victims`. Bind-before-who/where stays. [Cue-pending / Plan-not-ready](2026-08-21-refuse-complete-while-cue-pending.md) stays first. Multi-victim persist, LAN/DC leftover coerce, AD SRV hostname omit, `acceptedC2Ips` / `c2_domain` / extra-wan / CDN prefixes, and family persist stay.

Tests use synthetic RFC1918 / TEST-NET stand-ins.

## Alternatives considered

**Teach only methodology or ledger copy.** Rejected: a text-only stop after one bind still closes as completed.

**Auto-bind the leftover or invent who/where.** Rejected: bind-before-who/where stays. The model binds the leftover; persist writes a victim row only after that bind.

**Treat every unbound LAN IPv4 as a leftover workstation.** Rejected: IP-only harvest and DC / gateway / file-server leftovers (bind role `infra`, AD SRV locator, or LAN role hostname) must not block a single-victim close.

**Retune persist-every-bound-victim-row, LAN/DC coerce, or AD SRV hostname omit.** Rejected: those knobs are untested here and stay idle until a second victim is bound.

**Refuse complete until `case_report`.** Rejected: this check is leftover-bind complete only.

**Change agent-loop so `finish` kind=`stop` is not `completed`.** Rejected: new behavior belongs on the investigation plugin's existing `agent/turn-stopping` listener.

**Bake live-case gold IPs, MACs, hostnames, users, or the real AD domain into fixtures or notes.** Rejected: tests use bound victim `10.0.10.2`, leftover workstation `10.0.10.8` with hostname `lan-host-b`, DC/infra `10.0.10.3`, and TEST-NET C2 `198.51.100.80`.

## Testing

`packages/analyst/investigation/tests/mindset.spec.ts` pins `completeDenyReason`: leftover `10.0.10.8` (`lan-host-b`) after one bind names that unbound workstation; cue-pending and Plan-not-ready still win when those are open; binding the leftover, or leaving only DC/infra `10.0.10.3` (AD SRV or LAN role hostname), allows complete. `packages/analyst/investigation/tests/bind.spec.ts` pins `unboundHarvestedLanWorkstations` for hostname, human user, and non-infra MAC leftovers, empty leftovers for AD SRV / bind-role infra / LAN DC / file-server / gateway role hostnames, and `requireCaseReport` who/where staying on bound victim `10.0.10.2` without publishing `10.0.10.8`. `packages/analyst/investigation/tests/investigation.spec.ts` fires `agent/turn-stopping`: one bind plus leftover `lan-host-b` steers the named denial and writes no report; binding that leftover, or one bind with only DC/infra leftover, does not steer.

## Consequences

A text-only stop after one live bind cannot close a headless investigation as completed while another harvested LAN workstation remains unbound. The model sees the leftover. Binding that leftover, or having only DC / gateway / file-server leftover, allows complete again. Who/where/`victims` stay victim-only on bound rows.
