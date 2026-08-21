# Agent Note: Donate victim-IP-scoped MAC and hostname after a live bind

Status: implemented

English | [中文](2026-08-21-donate-victim-ip-scoped-mac-hostname.zh.md)

## Problem

Live lumma-r10 (`34b5b26`) bound the cited conversation correctly (LAN victim / external c2). `case_report` accepted. Close bar 3/5: IP, user, and full_name passed. MAC and hostname stayed ledger-only.

[Complete victim-row projection](2026-08-21-complete-victim-row-projection.md) donates a unique unaffiliated identity of a kind. User and full_name were unique after bind and donated. Other MAC and hostname values existed on the ledger (DC / other rows), so whole-ledger uniqueness donated neither gold value.

`entityIdForIdentity` affiliates a MAC only through `c2TalkingLanVictim` (a unique sourced `eth.src` pattern in evidence text, and a unique MAC on the whole ledger) or that uniqueness path. Hostname has no victim-IP path — uniqueness only. A second MAC or hostname anywhere on the ledger vetoes donate even when one value was harvested from `eth-src` / `name-service` scoped to the bound victim IP.

## Decision

After a live bind, donate MAC and hostname evidenced on the bound victim IP.

A hunt subject persisted as `evidence_id`, or a tool-result line scoped to that IP (`eth.src` with `ip.src ==` the victim, `name-service` with `ip.addr ==` the victim), affiliates that mac/hostname to the victim. Harvest stamps hunt-subject `evidence_id` on hostname from a `name-service` dump. A MAC stamps the talking IP on the line when present; a field-only `eth.src` dump stamps hunt-subject `scopeIp`, and a later victim-IP-scoped dump may fill a missing first-harvest `evidence_id` ([victim-IP-scoped restamp](2026-08-21-restamp-victim-ip-scoped-eth-src.md)). Hunt-subject `evidence_id` does not veto donate when later frames source that MAC from the victim ([talking-IP MAC stamp](2026-08-21-stamp-mac-evidence-from-talking-ip.md)). Whole-ledger uniqueness does not block a victim-IP-scoped identity. The persisted who/where carry that mac and hostname.

A distractor evidenced on another IP or carrying another `entity_id` stays out. Slots are not invented. Unique unaffiliated user and full_name still donate. Cue-as-victim stays refused and still issues [other-end](2026-08-21-other-end-hunt-on-cue-victim.md). [BindRelationship](../feature/2026-08-21-bind-relationship.md) still owns bind-before-close. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and idle LAN row.

## Alternatives considered

**Keep donate on whole-ledger uniqueness and `c2TalkingLanVictim` only.** Rejected: a DC or idle MAC/hostname on the ledger drops the victim-IP-scoped values that harvest already recorded.

**Donate every unaffiliated MAC or hostname of a kind.** Rejected: two unaffiliated macs with no victim-IP evidence must donate neither.

**Donate a MAC or hostname evidenced on another IP or tagged with another `entity_id`.** Rejected: distractors stay labeled and cannot fill who/where.

**Invent hostname or MAC slots that are not on the ledger.** Rejected: slots are not invented.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP, a TEST-NET peer, and an idle LAN row.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET peer (`198.51.100.80`), and idle row (`10.0.10.3`). After a live bind, a ledger with unaffiliated mac+hostname harvested from eth-src/name-service scoped to `10.0.10.2` plus a second mac+hostname affiliated with `10.0.10.3` persists the victim mac+hostname and omits the idle row. Two unaffiliated macs with no victim-IP evidence donate neither. Cue-as-victim stays refused. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same scoped ledger through `bind_relationship` then `case_report`.

## Consequences

A live bind writes victim mac and hostname when those values are evidenced on the bound victim IP, even if other MAC or hostname rows exist. User and full_name evidenced on a conversation whose client is the bound victim donate the same way ([conversation-client stamp](2026-08-21-stamp-user-fullname-from-conversation-client.md)). Two unscoped macs of the same kind still leave that slot empty. Cue-as-victim and inverted closes still fail unbound.
