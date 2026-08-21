# Agent Note: Drop locator leftovers and victim-containing CIDR from who/where coerce

Status: implemented

English | [中文](2026-08-21-drop-locator-cidr-from-handle-string-coerce.zh.md)

## Problem

Live fake-software r7 (`mta-2025-01-22` on `a0c6a15`, after [labeled handle-string coerce](2026-08-21-case-report-labeled-victim-handle-strings.md) and [DC/gateway-only MAC leftover](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md)) bound the cited conversation correctly (LAN victim / non-LAN C2). No `case_report` was accepted. Close calls were rejected unbound. Submitted who/where were labeled or sentence prose, not `{ entity_id }`.

[Labeled handle-string coerce](2026-08-21-case-report-labeled-victim-handle-strings.md) accepts a who/where string only when every leftover identity token is a victim-row handle. Locator leftovers (`Client`, `IP`, `located`, `at`, `on`, `network`) sit outside `HANDLE_WRAPPER_WORDS`, so they fail the handle check. `/` is a who/where delimiter, so a CIDR that contains the victim shatters into a leftover non-victim IPv4 (the network address) plus a leftover prefix number. Those leftovers poison an otherwise-correct victim-row string. [Omitted persist](2026-08-21-complete-omitted-victim-mac-user.md) never ran because nothing was accepted.

## Decision

After a live bind, `identityLikeTokens` treats locator leftovers `client` / `ip` / `located` / `at` / `on` / `network` as wrappers, not unmatched tokens. It extracts a leftover IPv4/prefix CIDR as one token before the delimiter split so `/` does not shatter it. `isVictimHandleText` then drops that CIDR when it contains the bound victim IP. Remaining victim-row handles still coerce the string onto `{ entity_id: victim }`.

LAN / gateway / DC leftovers and leftover LAN infra IPv4 / domain announcement tokens are [dropped separately](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.md). A leftover C2 IPv4, a distractor user or hostname, another leftover named non-infra IPv4 that is not that victim-containing CIDR, a CIDR that does not contain the victim, or unmatched leftover words still stay unbound. A string with no remaining victim-row handle stays unbound, except empty leftovers after LAN / gateway / DC drops. The DC/gateway NIC is not persisted. ip, hostname, user, and `full_name` are not dropped. Harvest stamps, bind accept/deny, omitted-mac persist, and C2-domain persist stay.

The hole is `isVictimHandleText` / `identityLikeTokens` / `HANDLE_WRAPPER_WORDS` in `packages/analyst/investigation/src/bind.ts`. Cue-as-victim stays refused. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` vs `DISTRACTOR_MAC`, and a synthetic LAN CIDR that contains that client.

## Alternatives considered

**Keep treating locator leftovers and a shattered CIDR as unmatched identity tokens.** Rejected: sentence wrappers around a correct victim IP, plus that victim's subnet CIDR, poison the handle check after a correct bind.

**Treat every leftover IPv4 or every leftover CIDR as a wrapper.** Rejected: a leftover C2 IPv4, another non-victim IPv4, or a CIDR that does not contain the victim must stay unbound.

**Coerce any string after a live bind to the victim.** Rejected: unmatched leftover words and non-victim identities must stay unbound.

**Drop leftover ip, hostname, user, or `full_name` the same way.** Rejected: those leftovers still decide victim versus C2.

**Change harvest stamps, bind accept/deny, omitted-mac persist, or C2-domain persist so a prose close becomes the victim.** Rejected: this knob is handle-string coerce after a live bind.

**Bake gold identities into harness code or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` / `DISTRACTOR_MAC`, and `10.0.10.0/24`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), `CLIENT_MAC`, `DISTRACTOR_MAC`, and LAN CIDR `10.0.10.0/24`. After a live bind, labeled who `Client IP: <LAN> / MAC Address: CLIENT_MAC` and sentence where `The client was located at <LAN> on the 10.0.10.0/24 network` coerce and accept. Persisted who/where are the victim row; `DISTRACTOR_MAC` stays off. Mixing C2 IPv4, a CIDR that does not contain the victim (`172.16.0.0/12`), or unmatched leftover words stays unbound. A string that is only that victim-containing CIDR stays unbound. Existing DC-only MAC leftover drop and cue-as-victim refuse stay. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same locator/CIDR close through `bind_relationship` then `case_report`.

## Consequences

A live bind plus a labeled or sentence who/where string writes the 5W1H packet when leftover identity tokens are victim-row handles even if locator wrappers or a CIDR that contains the victim remain. A C2 IPv4, distractor user or hostname, another IPv4, a CIDR that does not contain the victim, unmatched leftover words, or a string with no remaining victim-row handle still fails unbound. Cue-as-victim stays refused.
