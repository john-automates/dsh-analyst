# Agent Note: Keep submitted victim-row identities on accepted who/where

Status: implemented

English | [中文](2026-08-21-keep-submitted-victim-row-identities.zh.md)

## Problem

Live fake-software r1 (`mta-2025-01-22`) bound the cited conversation correctly (LAN victim / non-LAN C2). IP, MAC, and hostname persisted. `full_name` persisted because it donated. The model submitted `user` on who. `completeAcceptedSlot` dropped it because the projected victim row had no donated user.

[Persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md) copies donated projection keys, then ignores model-offered keys the row did not donate. That correctly strips a DC or gateway MAC that never appears as `eth.src` on the victim IP or in a victim-IP-scoped dump. It also drops a submitted user — and would drop hostname or `full_name` the same way — when remap onto the victim entity wipes a submitted victim-row identity.

## Decision

When projecting or remapping who/where onto the bound victim entity, keep a submitted user, hostname, or `full_name` if the model offered that key and the projected row has no donated value. Persist that user on accepted who/where. Do not invent a user the model never submitted.

A model-offered MAC or IP the row did not donate stays off. A submitted user, hostname, or `full_name` that donates to a different (non-victim) entity is not persisted. Donated ip/mac/hostname/`full_name` already on the row stay.

The hole is the empty-`projected[key]` branch in `completeAcceptedSlot`. MAC is not copied from the model.

[Persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md) still fills omitted keys from the row. [User/full_name conversation-client stamp](2026-08-21-stamp-user-fullname-from-conversation-client.md) still owns donate. Cue-as-victim stays refused. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, and idle or DC LAN row.

## Alternatives considered

**Keep ignoring every model-offered key the row did not donate.** Rejected: remap onto the victim entity wipes a submitted user the model already offered.

**Copy every model-offered slot key, including `mac`.** Rejected: a DC or gateway MAC that never appears as `eth.src` on the victim IP must stay off.

**Invent a user when the model omits the key and the row did not donate.** Rejected: slots the model never submitted are not invented.

**Persist a submitted user, hostname, or `full_name` that donates to a non-victim IP.** Rejected: those identities stay off the victim row.

**Drop donated ip/mac/hostname/`full_name` when keeping a submitted user.** Rejected: those slots already persist.

**Bake gold identities into harness code or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, and idle or DC LAN row.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), and idle or DC row (`10.0.10.3`). After a live bind, who/where that submit `user` (row has no donated user) persist that user and keep ip/mac/hostname/`full_name`. A submitted DC or gateway MAC stays off. A submitted user or hostname that donates to the non-victim IP is not persisted. An omitted user is not invented. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same submitted-user close through `bind_relationship` then `case_report`.

## Consequences

A live bind plus a submitted victim-row user writes that user even when the projected row did not donate it. A DC MAC still stays off. A user that donates to another entity does not persist. An omitted user is still not invented. Donated slots stay.
