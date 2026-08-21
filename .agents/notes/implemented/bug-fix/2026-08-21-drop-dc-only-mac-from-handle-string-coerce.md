# Agent Note: Drop DC/gateway-only MAC leftover from who/where coerce

Status: implemented

English | [中文](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.zh.md)

## Problem

Live fake-software r6 (`mta-2025-01-22` on `cd6c426`, after [labeled handle-string coerce](2026-08-21-case-report-labeled-victim-handle-strings.md) and [DC-only talking-IP persist](2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md)) bound the cited conversation correctly (LAN victim / non-LAN C2). No `case_report` was accepted. Close calls were rejected unbound. Submitted who/where were labeled or sentence strings, not `{ entity_id }`. where named a DC/gateway NIC plus leftover victim-row handles.

[Labeled handle-string coerce](2026-08-21-case-report-labeled-victim-handle-strings.md) accepts a who/where string only when every leftover identity token is a victim-row handle. A DC/gateway-only MAC is an unmatched leftover token, so the whole string stays unbound. [DC-only talking-IP persist](2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md) never ran because nothing was accepted. The gold client MAC stayed ledger-stuck on the DC.

## Decision

After a live bind, `identityLikeTokens` extracts a leftover colon or dash MAC as one token (colon is a who/where delimiter, so a word split would shatter it). `isVictimHandleText` then drops a leftover MAC that talking-IP frames source only from a non-victim — the same DC/gateway-only test as [persist](2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.md) (`macIsDcOrGatewayOnly`). Remaining victim-row handles still coerce the string onto `{ entity_id: victim }`. The existing omitted-mac path may then fill the unique non-DC-only client MAC.

A string that is only that DC/gateway-only MAC stays unbound. Leftover C2 IPv4, a distractor user or hostname, another non-victim IPv4, or unmatched words that are not field labels / sentence wrappers / quotes still stay unbound. The DC/gateway NIC is not persisted onto who/where. ip, hostname, user, and `full_name` are not dropped. Harvest stamps, bind accept/deny, and C2-domain persist stay.

The hole is `isVictimHandleText` / `identityLikeTokens` / `coerceIdentitySlotArg` in `packages/analyst/investigation/src/bind.ts`. Cue-as-victim stays refused. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, idle or DC LAN row, and synthetic `CLIENT_MAC` vs `DISTRACTOR_MAC`.

## Alternatives considered

**Keep requiring every leftover token, including a DC/gateway-only MAC, to be a victim-row handle.** Rejected: one DC/gateway NIC poisons an otherwise victim-row labeled or sentence string after a correct bind.

**Treat a leftover DC/gateway-only MAC as a victim-row handle.** Rejected: that would persist the DC/gateway NIC onto who/where.

**Drop every leftover MAC, or coerce any leftover token after a live bind.** Rejected: a leftover C2 IPv4, distractor user or hostname, another non-victim IPv4, or unmatched word must stay unbound. Absence of talking-IP evidence is not DC-only.

**Drop leftover ip, hostname, user, or `full_name` the same way.** Rejected: those leftovers still decide victim versus C2.

**Change harvest stamps, bind accept/deny, or C2-domain persist so a sticky DC row becomes the victim.** Rejected: this knob is handle-string coerce after a live bind.

**Bake gold identities into harness code or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, and synthetic `CLIENT_MAC` / `DISTRACTOR_MAC`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), `CLIENT_MAC`, and `DISTRACTOR_MAC` talking only from the idle/DC IP. After a live bind, labeled who or sentence where that names victim-row handles plus `DISTRACTOR_MAC` coerces and accepts. Persisted who/where are the victim row; `DISTRACTOR_MAC` stays off; unique non-DC-only `CLIENT_MAC` may fill via omitted persist. Mixing C2 IPv4, a distractor user, another non-victim IPv4, or unmatched leftover words stays unbound. A string that is only `DISTRACTOR_MAC` stays unbound. Cue-as-victim stays refused. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same mixed labeled/sentence close through `bind_relationship` then `case_report`.

## Consequences

A live bind plus a labeled or sentence who/where string writes the 5W1H packet when leftover identity tokens are victim-row handles even if a DC/gateway-only MAC is mixed in. Omitted persist can then fill a unique non-DC-only client MAC. The DC/gateway NIC stays off who/where. A C2 IPv4, distractor user or hostname, another IPv4, unmatched leftover words, or a string that is only that DC/gateway-only MAC still fails unbound. Cue-as-victim stays refused.
