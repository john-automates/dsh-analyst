# Agent Note: Coerce labeled and sentence victim-row handle strings

Status: implemented

English | [中文](2026-08-21-case-report-labeled-victim-handle-strings.zh.md)

## Problem

Live fake-software r4 (`cd66ca2`, after [omitted mac/user persist](2026-08-21-complete-omitted-victim-mac-user.md)) bound the cited conversation correctly (LAN victim / non-LAN C2). Two `case_report` calls were both rejected unbound. The model submitted labeled prose strings, not `{ entity_id }`:

- who: `User Account: <user> / Full Name: <full name> / MAC Address: <mac>` (the second call also added `Hostname: <host>`)
- where: a sentence naming the victim IP and hostname

[Handle-string coerce](2026-08-21-case-report-victim-handle-strings.md) already accepts a who/where string whose identity tokens are all victim-row handles. `identityLikeTokens` treated every leftover word as a token (`User`, `Account`, `Full`, `Name`, `MAC`, `Address`, `The`, `infected`, `host`, `was`, `identified`, `as`). Those fail the handle check. Space-split also breaks a multi-word `full_name`. `victimRowHandles` only included donated identities, so a gold MAC first donated to the DC was not a handle even when victim-IP frames sourced it.

Omitted mac/user persist never ran because nothing was accepted.

## Decision

After a live bind, `caseReportDenyReason` coerces a who/where string onto `{ entity_id: victim }` when every identity token in it is a victim-row handle (IP / MAC / hostname / user / `full_name`), even if the string also has field labels or a sentence wrapper. The existing complete-projection path then persists omitted mac/user.

Label words and sentence wrappers are not identity tokens. A multi-word `full_name` matches as one handle. A MAC, user, hostname, or `full_name` is a victim-row handle when it donates to the bound victim or is evidenced on that victim the same way omitted mac/user persist (victim-IP frames / conversation-client stamp). A sticky DC donate does not make a victim-IP-sourced MAC fail the handle check.

A string that names the C2, a distractor, another IPv4, or a non-victim identity stays unbound. Unmatched identity tokens still deny. Identities are not invented. Tokens are not swapped. Cue-as-victim stays refused.

The hole is `isVictimHandleText` / `identityLikeTokens` / `victimRowHandles` in `packages/analyst/investigation/src/bind.ts`. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` vs `DISTRACTOR_MAC`, and `lan-user` / `Lan User`.

## Alternatives considered

**Keep treating every leftover word as an identity token.** Rejected: field labels and sentence wrappers fail the handle check after a correct bind.

**Coerce any string after a live bind to the victim.** Rejected: a string that names the C2, a distractor, another IPv4, or unmatched identity tokens must stay unbound.

**Keep `victimRowHandles` as donated identities only.** Rejected: a MAC first donated to the DC and later sourced from victim-IP frames must still be a handle so omitted persist can run.

**Change `entityIdForIdentity` so an explicit DC `entity_id` loses to victim-IP frames.** Rejected: this knob is handle-string coerce. Affiliation and role labels stay.

**Invent identities, swap tokens, or accept cue-as-victim.** Rejected: slots are not invented, inversion stays unbound, and cue-as-victim stays refused.

**Bake gold identities into harness code or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` / `DISTRACTOR_MAC`, and `lan-user` / `Lan User`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), `CLIENT_MAC`, `DISTRACTOR_MAC`, `lan-user`, `Lan User`, and `lan-host`. After a live bind, labeled who `User Account: lan-user / Full Name: Lan User / MAC Address: CLIENT_MAC` coerces and accepts. A sentence where naming the victim IP and hostname coerces and accepts. The same strings that also name the C2 or a DC MAC stay unbound. Unmatched prose without identity tokens stays unbound. After coerce, omitted mac/user persist from victim-IP frames / conversation-client evidence when a sticky DC donate left the projected row empty. ip/hostname already on the row stay. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same labeled/sentence close through `bind_relationship` then `case_report`.

## Consequences

A live bind plus a labeled or sentence who/where string writes the 5W1H packet when every identity token is a victim-row handle. Omitted mac/user persist can then fill a sticky-DC row. A string that names the C2, a distractor, another IPv4, or unmatched identity tokens still fails unbound. Cue-as-victim stays refused.
