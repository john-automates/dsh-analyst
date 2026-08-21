# Agent Note: Persist a harvested human user onto omitted who after a live bind

Status: implemented

English | [中文](2026-08-21-persist-harvested-human-on-omitted-who.zh.md)

## Problem

Live fake-r25 (`3fafd8f`) bound the cited conversation correctly (LAN victim / non-LAN C2). Identity leftover 3/4: IP / MAC / hostname HIT. The gold user was harvested. Accepted where had that user. Accepted who omitted `user`. The grader who-haystack misses the user when who omits it.

[Complete omitted victim-row mac and user](2026-08-21-complete-omitted-victim-mac-user.md) fills omitted user from victim-IP evidence (conversation-client stamp). [Keep submitted victim-row identities](2026-08-21-keep-submitted-victim-row-identities.md) keeps a submitted user on the slot that offered it. [Fold sibling identity keys](2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md) folds sibling `user` only when the whole who/where argument is omitted. Uniqueness donate still counts machine SAMs ending in `$`, so a harvested human plus a machine account leaves `projectVictimSlot.user` empty. A present who object that omits the `user` key then has no donated value and no conversation-client stamp, so `completeAcceptedSlot` leaves who.user off while where already has the harvested human.

## Decision

After a live bind, persist a harvested human user onto omitted who/where when uniqueness donate left the projected row empty because machine SAMs also exist.

`omittedUserEvidencedOnVictim` still returns a conversation-client user first. When no such stamp exists, it returns the unique harvested human user (machine SAM ending in `$` ignored and not persisted). A user that donates to a non-victim stays off. Two humans still persist none. A submitted machine SAM still stays off and does not fall through to that harvest. Where that already has the user is unchanged. Who/where stay victim-only. Slots are not invented.

[Persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md) still copies donated projection keys. [Complete omitted victim-row mac and user](2026-08-21-complete-omitted-victim-mac-user.md) still owns conversation-client omitted user. Uniqueness donate still counts every unaffiliated user, including machine SAMs. [Keep submitted](2026-08-21-keep-submitted-victim-row-identities.md) and [sibling fold](2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.md) stay. Cue-as-victim stays refused. Fastly / akamaized / extras persist width / authenticatoor stay out of this change.

## Alternatives considered

**Keep requiring a conversation-client stamp for omitted user when the projected row is empty.** Rejected: a present who object that omits `user` drops a harvested human that where already persisted.

**Change uniqueness donate so a human SAM wins when machine accounts also exist.** Rejected: this knob is omitted persist on the accepted packet. Affiliation and donate stay. A submitted machine SAM must still stay off rather than lose to a donated human.

**Copy accepted where.user onto omitted who without a harvest check.** Rejected: who/where stay victim-only; a user that donates to a non-victim must stay off who.

**Persist a machine SAM ending in `$` as user.** Rejected: a machine account is not a victim user.

**Bake the live-case username into harness code or tests, invent evals, or retune Fastly / akamaized / extras persist.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, `lan-user`, and machine SAM `lan-host$`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), `CLIENT_MAC`, `DISTRACTOR_MAC`, `lan-user` / `Lan User`, and machine SAM `lan-host$`. After a live bind, a ledger with harvested `lan-user` plus `lan-host$` and no conversation-client stamp leaves `projectVictimSlot.user` empty. `case_report` who that omits `user` while where already has `lan-user` persists `lan-user` on who and keeps it on where. A submitted machine SAM on who stays off. Two humans persist none on omitted who. Cue-as-victim stays refused. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same omitted-who close through `bind_relationship` then `case_report`.

## Consequences

A live bind plus a harvested unique human user writes that user onto omitted who even when a machine SAM blocked uniqueness donate and where already has the user. A machine SAM still stays off. Two humans still persist none. Conversation-client omitted user, submitted keep, and sibling fold stay. Donated ip / mac / hostname / `full_name` stay.
