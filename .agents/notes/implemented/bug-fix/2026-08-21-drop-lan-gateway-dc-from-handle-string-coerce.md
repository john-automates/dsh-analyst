# Agent Note: Drop LAN/gateway/DC leftovers from who/where coerce

Status: implemented

English | [中文](2026-08-21-drop-lan-gateway-dc-from-handle-string-coerce.zh.md)

## Problem

Live fake-software r26 (`mta-2025-01-22` on `4558993`, after [locator/CIDR leftovers](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md), [DC/gateway-only MAC leftover](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md), and [persist harvested human on omitted who](2026-08-21-persist-harvested-human-on-omitted-who.md)) bound the cited conversation correctly (LAN victim / non-LAN C2). No `case_report` was accepted. Close calls were rejected unbound. Submitted where was LAN / gateway / DC / AD-domain prose plus leftover gateway/DC IPv4s, not `{ entity_id }`. The model also mixed a leftover DC/gateway-only MAC.

[Locator/CIDR leftovers](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md) treat `client` / `ip` / `located` / `at` / `on` / `network` as wrappers and drop a leftover CIDR that contains the bound victim IP. [DC/gateway-only MAC leftover](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md) drops a leftover MAC that talking-IP frames source only from a non-victim. LAN / gateway / DC / AD-domain role words sit outside `HANDLE_WRAPPER_WORDS`. Leftover gateway/DC IPv4s stay unmatched tokens. Those leftovers poison an otherwise-correct close after a correct bind. [Omitted persist](2026-08-21-complete-omitted-victim-mac-user.md) never ran because nothing was accepted.

## Decision

After a live bind, `identityLikeTokens` treats LAN / gateway / DC / AD-domain leftovers `lan` / `gateway` / `dc` / `ad` / `domain` / `workgroup` / `controller` as wrappers. `isVictimHandleText` then drops a leftover LAN IPv4 that is bind role `infra`, or that talking-IP frames source a DC/gateway-only MAC from, when that IPv4 is not a leftover named non-infra bind handle. It drops a leftover dotted name that is not a victim-row handle and is not C2-stamped (attested C2 dest or donate to a non-LAN entity). Remaining victim-row handles still coerce the string onto `{ entity_id: victim }`. Empty leftovers after those drops coerce to the victim row when those wrappers or leftover LAN infra IPv4 / domain announcement tokens were present. The projected victim row persists. The DC/gateway NIC is not persisted onto who/where.

A leftover C2 IPv4, a leftover C2-stamped DNS name, a distractor user or hostname, another leftover named non-infra IPv4, a CIDR that does not contain the victim, or unmatched leftover words still stay unbound. A string that is only that DC/gateway-only MAC, or only that victim-containing CIDR, and has no LAN / gateway / DC / AD-domain wrappers or leftover LAN infra IPv4, stays unbound. Live-case hostnames and IPv4s are not listed. ip, hostname, user, and `full_name` that are leftover handles are not dropped. Harvest stamps, bind accept/deny, omitted persist, and C2-domain persist stay.

The hole is `isVictimHandleText` / `identityLikeTokens` / `HANDLE_WRAPPER_WORDS` in `packages/analyst/investigation/src/bind.ts`. Cue-as-victim stays refused. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` vs `DISTRACTOR_MAC`, a synthetic gateway IPv4, and a synthetic dotted AD-domain token.

## Alternatives considered

**Keep treating LAN / gateway / DC / AD-domain leftovers as unmatched identity tokens.** Rejected: role wrappers around leftover gateway/DC IPv4s poison the handle check after a correct bind.

**Treat every leftover LAN IPv4 as a wrapper.** Rejected: a leftover named non-infra bind endpoint, including an idle LAN IPv4 submitted as who/where, must stay unbound.

**Treat every leftover dotted name as a wrapper.** Rejected: a leftover C2-stamped DNS name must stay unbound.

**Coerce any string after a live bind to the victim.** Rejected: unmatched leftover words and leftover non-victim handles must stay unbound.

**Drop leftover ip, hostname, user, or `full_name` the same way.** Rejected: those leftovers still decide victim versus C2.

**Change harvest stamps, bind accept/deny, omitted persist, or C2-domain persist so a prose close becomes the victim.** Rejected: this knob is handle-string coerce after a live bind.

**Bake gold identities into harness code or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` / `DISTRACTOR_MAC`, gateway `10.0.10.1`, and `ad.example.lan`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), gateway `10.0.10.1`, infra `10.0.10.4`, `CLIENT_MAC`, `DISTRACTOR_MAC`, and `ad.example.lan`. After a live bind that does not name the DC/gateway as a non-infra endpoint, where `ad.example.lan LAN, gateway 10.0.10.1, DC 10.0.10.3` plus `DISTRACTOR_MAC` coerces and accepts. Wrappers-only `LAN, gateway, DC` coerces. Bind role `infra` leftover IPv4 coerces. Persisted who/where are the victim row; `DISTRACTOR_MAC`, gateway/DC IPv4s, and the AD-domain token stay off. Mixing C2 IPv4, a leftover C2-stamped DNS name, a distractor user, or unmatched leftover words stays unbound. A string that is only `DISTRACTOR_MAC` or only the victim-containing CIDR stays unbound. Existing locator/CIDR, DC-only MAC leftover drop, labeled-handle coerce, and cue-as-victim refuse stay. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same LAN/gateway/DC close through `bind_relationship` then `case_report`.

## Consequences

A live bind plus a who/where string writes the 5W1H packet when leftover identity tokens are victim-row handles even if LAN / gateway / DC / AD-domain wrappers, leftover LAN infra IPv4s, a leftover domain / workgroup announcement, or a leftover DC/gateway-only MAC remain. Empty leftovers after those drops coerce to the projected victim row. A C2 IPv4, a leftover C2-stamped DNS name, a distractor user or hostname, another leftover named non-infra IPv4, unmatched leftover words, or a string that is only that DC/gateway-only MAC or only that victim-containing CIDR still fails unbound. Cue-as-victim stays refused.
