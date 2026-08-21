# Agent Note: Complete the victim-row projection after a live bind

Status: implemented

English | [中文](2026-08-21-complete-victim-row-projection.zh.md)

## Problem

Live lumma-r8 (`53a223d`) bound the cited conversation correctly (LAN victim / external c2). No cue-as-victim. Two `case_report` calls were denied as prose; a `report.md` write was denied; the third accepted `who.entity_id` as a user handle and `where.entity_id` as the victim IP. The persisted `investigation/report` who/where both became `{ entity_id: victim.addr, ip: victim.addr }` only. The submitted user handle was rewritten to the IP and dropped. MAC, hostname, user, and full_name were on the ledger and in the printed report, not in accepted who/where. Close bar 1/5 (IP only).

`projectVictimSlot` already copies mac/hostname/user from donated identities, but `entityIdForIdentity` only affiliates an explicit `entity_id`, `kind=ip`, or a MAC via `c2TalkingLanVictim`. Harvest records user/hostname/mac/full_name without `entity_id`, so they stay on the ledger and do not donate. `CaseIdentitySlot` has no `full_name` field, so that slot cannot persist even if donated.

## Decision

After a live bind, complete the victim-row projection.

`CaseIdentitySlot` has optional `full_name`. `projectVictimSlot` copies it with mac/hostname/user.

An unaffiliated ledger identity (no `entity_id`, `evidence_id` does not point at a non-victim) donates to the bound victim when it is the only identity of that kind that is not affiliated with a different entity. Identities whose `entity_id` is already the victim still donate. A distractor with `entity_id` of another endpoint still does not. Slots are not invented. A kind with two unaffiliated values donates neither. A MAC or hostname evidenced on the bound victim IP still donates when other values of that kind exist ([victim-IP-scoped donate](2026-08-21-donate-victim-ip-scoped-mac-hostname.md)).

The persisted `investigation/report` who/where carry ip/mac/hostname/user/full_name from that projection. Handle-string coerce still maps to `{ entity_id: victim.addr }`; the row fills from the ledger, not from free text. Keys the model omitted, including `mac`, are filled from that same row ([persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md)).

[BindRelationship](../feature/2026-08-21-bind-relationship.md) still owns bind-before-close. [Victim-row handles](2026-08-21-case-report-victim-row-entity-id.md) still persist the victim address. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client and a TEST-NET peer.

## Alternatives considered

**Keep donation on explicit `entity_id` or a sourced MAC only.** Rejected: harvest already wrote the row onto the ledger; the live close dropped every slot except IP.

**Donate every unaffiliated identity of a kind.** Rejected: two unaffiliated users of the same kind must donate neither.

**Donate a distractor whose `entity_id` is another endpoint.** Rejected: distractors stay labeled and cannot fill who/where.

**Fill who/where from the submitted handle string.** Rejected: the handle is coerce-only; the row comes from the ledger. Slots are not invented.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP and a TEST-NET peer.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`) and TEST-NET peer (`198.51.100.80`). After a live bind, a ledger with unaffiliated mac/hostname/user/full_name plus a distractor user whose `entity_id` is another LAN IP persists the victim row (all five slots) and omits the distractor. Two unaffiliated users of the same kind donate neither user. Cue-as-victim stays refused. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same unaffiliated ledger through `bind_relationship` then `case_report` and persists `investigation/report` with those five slots.

## Consequences

A live bind plus harvested unaffiliated identities writes the full victim row. A handle string or `entity_id` still stores the victim address. Two unaffiliated values of one kind leave that slot empty. Cue-as-victim and inverted closes still fail unbound.
