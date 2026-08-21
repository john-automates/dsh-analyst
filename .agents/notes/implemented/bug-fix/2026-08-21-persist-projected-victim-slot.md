# Agent Note: Persist the projected victim row when case_report omits slot keys

Status: implemented

English | [中文](2026-08-21-persist-projected-victim-slot.zh.md)

## Problem

Live lumma-r16 (`e2da3b4`) bound the cited conversation correctly (LAN victim / external c2). Identity 4/5. C2 orientation and family extra passed. `whitepepper.su` failed. MAC failed: the gold MAC was ledger-only. Accepted who/where had ip/hostname/user/full_name and no `mac` key. The model printed a DC MAC; that value never persisted.

[Complete victim-row projection](2026-08-21-complete-victim-row-projection.md) and [victim-IP-scoped donate](2026-08-21-donate-victim-ip-scoped-mac-hostname.md) already copy a donated MAC onto `projectVictimSlot`. The close path still persisted the model's who/where object. When the model omitted `mac`, the accepted packet had no mac even when the bound victim row had a victim-IP-sourced MAC.

## Decision

After a live bind, persist the projected victim row, not the model's partial keys.

Model-supplied who/where still go through the existing deny/coerce path first. After a live bind, omitted who/where also fold sibling top-level identity keys (`ip`, `mac`, `hostname`, `user`, `full_name`) from the same `case_report` arguments into that submitted slot ([fold sibling identity keys](2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md)). Accepted who/where are `completeAcceptedSlot` of that projected row: `entity_id`, `ip`, donated mac/hostname/user/full_name, a submitted user/hostname/full_name the row did not donate when that identity does not donate to a different entity ([keep submitted victim-row identities](2026-08-21-keep-submitted-victim-row-identities.md)), and a submitted mac that is not DC/gateway-only ([keep submitted victim MAC unless DC-only](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md)). A submitted human user is kept without a conversation-client stamp. A machine SAM ending in `$` is not persisted as user. Keys the model omitted are filled from the row. Omitted mac and user also persist from victim-IP evidence when a sticky DC donate or uniqueness left the row empty ([complete omitted victim-row mac and user](2026-08-21-complete-omitted-victim-mac-user.md)). A unique harvested human user also persists onto omitted who/where when machine SAMs blocked uniqueness donate ([persist harvested human on omitted who](2026-08-21-persist-harvested-human-on-omitted-who.md)). An AD SRV / DC locator hostname does not persist as who/where hostname; a submitted or harvested workstation hostname is kept ([omit AD SRV locator hostname](2026-08-21-omit-ad-srv-locator-hostname.md)). A MAC donates when it is evidenced on the bound victim IP ([talking-IP stamp](2026-08-21-stamp-mac-evidence-from-talking-ip.md)) or restamped from a victim-IP-scoped field-only `eth.src` dump ([victim-IP-scoped restamp](2026-08-21-restamp-victim-ip-scoped-eth-src.md), including [overwrite of a DC/peer first stamp](2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.md)). A DC or gateway MAC that never appears as `eth.src` on the victim IP or in a victim-IP-scoped dump stays off. Other donated slots stay when mac is filled. Slots are not invented.

[Both-LAN bind refuse](2026-08-21-refuse-both-lan-bind.md) and [bind coerce](2026-08-21-bind-relationship-stringified-args.md) stay. [Cue-as-victim](2026-08-21-refuse-cue-as-victim.md) stays refused. No new slots.

[BindRelationship](../feature/2026-08-21-bind-relationship.md) still owns bind-before-close. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and LAN DC.

## Alternatives considered

**Keep persisting the model's who/where object after deny.** Rejected: an omitted `mac` dropped a victim-IP-sourced MAC that `projectVictimSlot` already had.

**Fill mac only, and drop ip/hostname/user/full_name when completing the row.** Rejected: those r15 slots stay when they donate.

**Donate a DC or gateway MAC that never appears as eth.src on the victim IP.** Rejected: those NICs stay off the victim row.

**Invent a MAC that is not on the ledger or not victim-sourced.** Rejected: slots are not invented.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET peer, and LAN DC.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET peer (`198.51.100.80`), and LAN DC (`10.0.10.3`). After a live bind, a ledger with victim-sourced `CLIENT_MAC` plus a DC MAC, then `case_report` who/where without a `mac` key, persists `CLIENT_MAC` on both who and where and keeps ip/hostname/user/full_name. The DC MAC stays off. A ledger with no victim-sourced MAC leaves `who.mac` absent. Cue-as-victim stays refused. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same omitted-mac close through `bind_relationship` then `case_report`.

## Consequences

A live bind plus a victim-IP-sourced MAC writes that mac even when the model omits the key. A DC MAC that is not sourced from the victim IP does not persist. Other donated slots stay. Cue-as-victim, both-LAN, and inverted closes still fail unbound.
