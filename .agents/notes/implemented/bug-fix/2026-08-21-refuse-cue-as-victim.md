# Agent Note: Refuse cue/observation address as victim

Status: implemented

English | [中文](2026-08-21-refuse-cue-as-victim.zh.md)

## Problem

Live lumma-r7 (`ac6f879`) Bind #1 denied correctly: victim was the cue/observation address and `because` did not cite the conversation. Bind #2 accepted an inverted bind: victim = the cue/observation address, c2 = the LAN DC, `because` cited the conversation (`evidence_id`, both endpoints, port, talking/packet/flow/peer). Two later `case_report` calls sent a ledger user as `who` and the cue address as `where`; both returned unbound. The user is not a handle on that inverted victim row, so [victim-row handle-string coerce](2026-08-21-case-report-victim-handle-strings.md) did not fire. Cue-as-victim was supposed to stay refused.

`resolveEndpoint` unbound a cue/observation `victim` only when `because` failed `citesConversation`. A conversation cite was enough to keep the detector IP as victim.

## Decision

A cue/observation address cannot be victim. `role === 'victim' && isCueObservationAddr(addr)` always returns `UNBOUND_REASON`. `isCueObservationAddr` is a unicast non-LAN IPv4; a hostname is not a cue. Cue/observation addresses still default to `c2`. Tokens are not swapped. Exactly one victim. An inverted `case_report` is refused. Victim-row handle-string coerce remains for a live non-inverted bind.

[BindRelationship](../feature/2026-08-21-bind-relationship.md) still owns bind-before-close. Scout, leftover-report bans, harvest affiliation, and new evals stay out of this change. Tests use a synthetic LAN client and a TEST-NET peer.

## Alternatives considered

**Keep the conversation-cite exception.** Rejected: live Bind #2 cited the conversation and inverted victim/c2.

**Silently assign the cue to `c2` when the model sends `victim`.** Rejected: tokens are not swapped. Refuse the bind.

**Silently swap an inverted victim/c2 pair.** Rejected: that is the archived rewrite. Inversion still fails unbound.

**Teach only the methodology prompt or the tool description.** Rejected: Bind #2 would still accept.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP and a TEST-NET cue.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`) and TEST-NET peer (`198.51.100.80`). Assigning `victim` to the TEST-NET address is denied when `because` is an alert string and when it cites the conversation, `evidence_id`, both endpoints, or `dport`. LAN victim plus TEST-NET `c2` still binds, and `case_report` still closes. `packages/analyst/investigation/tests/investigation.spec.ts` denies a conversation-cited cue-as-victim bind through `tools.execute`.

## Consequences

An inverted cue-as-victim bind stays unbound. A live LAN-victim bind still closes, and handle-string coerce still requires a non-inverted victim row.
