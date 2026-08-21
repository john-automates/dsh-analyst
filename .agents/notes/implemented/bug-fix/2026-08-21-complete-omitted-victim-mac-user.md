# Agent Note: Complete omitted victim-row mac and user after a live bind

Status: implemented

English | [中文](2026-08-21-complete-omitted-victim-mac-user.zh.md)

## Problem

Live fake-software r3 (`mta-2025-01-22`) bound the cited conversation correctly (LAN victim / non-LAN C2). [Keep submitted victim MAC unless DC-only](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md) was untested: the model submitted only `{ entity_id: victim }`. Projection filled ip, hostname, and `full_name`. Accepted who/where had no mac and no user.

The gold MAC was first stamped and donated to the DC. Victim-IP frames sourced that same MAC (`ip.src` / outbound / ARP `is at`). `entityIdForIdentity` lets an explicit DC `entity_id` / sticky DC donate win, so `projectVictimSlot` omitted mac. The user was not unique-unaffiliated, so it was not donated either. `completeAcceptedSlot` only fills omitted keys from that projected row, so the entity_id-only close stayed thin.

DC/gateway-only MACs stayed off. A submitted victim MAC must still persist.

## Decision

After a live bind, persist omitted `mac` and `user` onto accepted who/where even when the model submits only `entity_id`.

A MAC first donated to the DC still fills the omitted mac slot when it is the unique ledger MAC that is not DC/gateway-only. [DC-only MAC is exclusive non-victim talking-IP](2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md) owns that test. A sticky DC `entity_id` or `evidence_id` does not hide a NIC that is not proven DC-only. Several equally unproven MACs persist none. A user evidenced on the bound victim (conversation-client stamp, or a Kerberos/SAMR conversation whose client is that IP) fills omitted user even when uniqueness would block. A unique harvested human user also fills omitted who/where when machine SAMs blocked uniqueness donate ([persist harvested human on omitted who](2026-08-21-persist-harvested-human-on-omitted-who.md)). Do not invent a user. Do not persist a user that donates to a non-victim and is not evidenced on the victim.

Do not drop ip/hostname/`full_name`. Do not invent a MAC when several ledger MACs are equally unproven. DC/gateway-only MACs stay off.

[Keep submitted victim MAC unless DC-only](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md) stays: a submitted victim MAC still persists; a submitted DC-only MAC still stays off. [Persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md) still copies donated projection keys. Donate and `entityIdForIdentity` stay: an explicit DC `entity_id` still wins affiliation. The hole is the empty-`projected[key]` branch in `completeAcceptedSlot` when the model omits mac/user.

Cue-as-victim stays refused. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` vs `DISTRACTOR_MAC`, and `lan-user` vs a distractor user.

## Alternatives considered

**Keep filling omitted keys only from donated projection keys.** Rejected: an entity_id-only close drops a victim-IP-sourced MAC and a conversation-client user after a sticky DC donate.

**Change `entityIdForIdentity` / `identityDonatesToVictim` so an explicit DC `entity_id` loses to victim-IP frames.** Rejected: this knob is omitted persist on accepted who/where. Affiliation and role labels stay.

**Copy every omitted ledger MAC or user onto the victim row.** Rejected: a DC/gateway-only MAC and a user that donates to a non-victim must stay off.

**Invent a MAC or user when the row and frames do not evidence one.** Rejected: slots are not invented.

**Drop ip/hostname/`full_name` when completing omitted mac/user.** Rejected: those slots already persist.

**Drop keep-submitted-mac when completing an omitted victim MAC.** Rejected: a submitted victim MAC still persists; a submitted DC-only MAC still stays off.

**Bake gold identities into harness code or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` / `DISTRACTOR_MAC`, and `lan-user` vs a distractor user.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), `CLIENT_MAC`, `DISTRACTOR_MAC`, `lan-user`, and a distractor user. After a live bind, who/where that submit only `{ entity_id: victim }` persist `CLIENT_MAC` when it is the unique non-DC-only ledger MAC even if the ledger first donated that MAC to the DC. An omitted user evidenced on the victim conversation client persists even when uniqueness would block. A DC-only `DISTRACTOR_MAC` stays off. A user that donates to a non-victim is not persisted. ip/hostname/`full_name` stay. An omitted mac is not invented when several MACs are equally unproven. A submitted victim MAC still persists. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same entity_id-only close through `bind_relationship` then `case_report`.

## Consequences

A live bind plus an entity_id-only close writes omitted mac when that MAC is the unique non-DC-only ledger value, and omitted user when victim-IP evidence exists, even if a sticky DC donate left the projected row empty. A DC/gateway-only MAC still stays off. A user that donates to a non-victim still stays off. Several equally unproven MACs still persist none. Submitted victim MAC keep stays. Donated ip/hostname/`full_name` stay.
