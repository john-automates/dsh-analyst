# Agent Note: Omit LAN DC / file-server / gateway role hostnames from leftover harvested workstations

Status: implemented

English | [中文](2026-08-22-omit-lan-infra-role-hostnames-from-leftover.zh.md)

## Problem

After a live bind, [refuse complete while a harvested LAN workstation is unbound](2026-08-21-refuse-complete-while-unbound-workstation.md) correctly names a leftover harvested workstation. The same leftover list can also name a LAN DC, file-server, or gateway when that IPv4 already has a hostname or MAC. Those hosts are infra. A NetBIOS or DNS role name such as `*-DC`, `*FILESERVER*`, `*FILE-SERVER*`, or `gateway` is not an AD SRV / DC locator, so the leftover classifier treated it as workstation identity.

[Refuse complete](2026-08-21-refuse-complete-while-unbound-workstation.md) stays. Bind-before-who/where stays. Unbound hosts are not persisted onto who/where.

## Decision

`unboundHarvestedLanWorkstations` omits DC / file-server / gateway infra even when those IPv4s have a hostname or MAC. Leftover infra is bind role `infra`, an IPv4 already affiliated with an AD SRV / DC locator hostname, and an IPv4 affiliated with a LAN DC / file-server / gateway role hostname. The first NetBIOS/DNS label matches `*-dc`, `dc`, `*fileserver*`, `*file-server*`, or `gateway`. A workstation `desktop-*` does not match. A `.1` LAN IPv4 is infra only when it is already known as gateway or infra.

`workstationIdentityOn` does not treat those role names as workstation identity. `completeDenyReason` still names leftover harvested workstations and is not retuned. A leftover harvested workstation still denies complete. A single-victim case whose only other LAN identities are DC / gateway / file-server completes after one bind. The denial does not name the DC. Who/where persist still uses only the AD SRV locator omit.

Tests use synthetic RFC1918 / TEST-NET stand-ins.

## Alternatives considered

**Treat every non-AD-SRV hostname as workstation identity.** Rejected: a DC / file-server / gateway role name then appears on the leftover list and in the complete-deny text.

**Retune refuse-complete, multi-victim persist, LAN/DC leftover coerce, or AD SRV hostname omit on who/where.** Rejected: this knob is leftover infra membership.

**Treat every `.1` LAN IPv4 as a gateway.** Rejected: `.1` is infra only when already known as gateway or infra. A leftover workstation on `.1` still denies complete.

**Auto-bind infra or persist an unbound host onto who/where.** Rejected: bind-before-who/where stays.

**Bake live-case gold IPs, MACs, hostnames, users, or the real AD domain into fixtures or notes.** Rejected: tests use bound victim `10.0.10.2` hostname `lan-host`, leftover workstation `10.0.10.8` hostname `lan-host-b`, DC `10.0.10.3` hostname `lan-dc` or `TEST-DC`, file-server `10.0.10.4` hostname `lan-fileserver`, gateway `10.0.10.1` hostname `gateway`, and TEST-NET C2 `198.51.100.80`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` pins `unboundHarvestedLanWorkstations`: leftover `10.0.10.8` (`lan-host-b`) remains after one bind; DC `lan-dc` / `TEST-DC`, file-server `lan-fileserver` / `lan-file-server`, and gateway `gateway` are empty leftovers even with a MAC; a `.1` IPv4 with workstation hostname `desktop-test01` remains leftover; `requireCaseReport` who/where stay on bound victim `10.0.10.2` without publishing `10.0.10.8`. `packages/analyst/investigation/tests/mindset.spec.ts` pins `completeDenyReason`: leftover `lan-host-b` plus DC / file-server / gateway role names still names only that workstation; only those role-name leftovers allow complete. `packages/analyst/investigation/tests/investigation.spec.ts` fires `agent/turn-stopping`: one bind plus leftover `lan-host-b` and DC / file-server / gateway role names steers the named workstation denial and does not name the DC; one bind with only those role-name leftovers does not steer.

## Consequences

Complete-deny leftover text names harvested workstations and omits DC / file-server / gateway. A single-victim close still proceeds when only those leftovers remain. Refuse-complete, who/where persist, and bind-before-who/where stay.
