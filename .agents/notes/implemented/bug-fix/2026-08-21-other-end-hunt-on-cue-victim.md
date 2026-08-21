# Agent Note: Other-end hunt on cue-as-victim deny

Status: implemented

English | [中文](2026-08-21-other-end-hunt-on-cue-victim.zh.md)

## Problem

Live lumma-r9 (`5400341`) never armed victim-row donate because bind never succeeded. Bind fired twice; both were rejected unbound ([refuse cue-as-victim](2026-08-21-refuse-cue-as-victim.md) working): victim = cue/C2 and c2 = LAN DC, then victim = c2 = the same cue address. `case_report` then rejected unbound. No `investigation/bind` or `investigation/report`. The gold LAN IP and hostname never appeared in the session. The gold MAC was ledger-only. User and full_name were ledger plus the rejected report only. The model inverted the cue, then quit instead of hunting the LAN peer. Runtime 70s, exit 0.

The detector IP is a hypothesis about the other end. Stopping at `UNBOUND_REASON` named the rule and not the hunt.

## Decision

When `bind_relationship` is rejected because the assigned victim is a cue/observation address (`isCueObservationAddr` / non-LAN unicast), the plugin issues an `other-end` hunt whose subject is that cue IP. The filter is `ip.dst == <cue>` and the field is `ip.src`. Tokens are not swapped. The LAN peer is not invented.

The deny text names that hunt and filter: `unbound: hunt LAN ip.src talking to <cue> (ip.dst == <cue>).` A later bind that still assigns that cue, or any cue, as victim stays denied and repeats the hunt name. Cue-as-victim never becomes a live bind.

When `autoHunt` is true, `other-end` auto-runs through `pcap_filter` like other issued hunts, even though its subject is the cue. [Identity-hunt auto-run](2026-08-21-auto-run-outstanding-identity-hunts.md) still skips non-LAN subjects for `eth-src`, `name-service`, Kerberos, and SAMR.

`case_report` stays unbound (`UNBOUND_REASON`) until a live bind with a non-cue victim exists. A correct LAN-victim / cue-c2 bind is accepted without this hunt when the model already has the LAN peer. Victim-row donate still requires that live bind.

[Refuse cue-as-victim](2026-08-21-refuse-cue-as-victim.md) still owns the refuse. [BindRelationship](../feature/2026-08-21-bind-relationship.md) still owns bind-before-close. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client and a TEST-NET peer.

## Alternatives considered

**Stop at `UNBOUND_REASON` after a correct refuse.** Rejected: lumma-r9 refused twice and quit. The deny must name the other-end hunt.

**Silently assign the cue to `c2`, or swap an inverted pair.** Rejected: tokens are not swapped. [Refuse cue-as-victim](2026-08-21-refuse-cue-as-victim.md) stays.

**Invent the LAN IP in the deny text, prompt, or tests.** Rejected: the hunt finds LAN `ip.src`; gold addresses are not expected answers.

**Accept the invert on a second cue-as-victim bind.** Rejected: cue-as-victim never becomes a live bind.

**Teach only the methodology prompt or the tool description.** Rejected: the refuse already existed and the model still quit.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP and a TEST-NET cue.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` and `hunts.spec.ts` use a synthetic LAN client (`10.0.10.2`) and TEST-NET peer (`198.51.100.80`). Assigning `victim` to the TEST-NET address is denied, names `other-end` for that address, and does not invent the LAN IP. `packages/analyst/investigation/tests/investigation.spec.ts` records the hunt through `tools.execute`, denies a second cue-as-victim bind with the same hunt name, auto-runs `ip.dst == 198.51.100.80` / `ip.src` when a stub `pcap_filter` is mounted, harvests `10.0.10.2` from that dump, then accepts a LAN-victim / TEST-NET-c2 bind and lets `case_report` close. Cue-as-victim never writes `investigation/bind`.

## Consequences

A cue-as-victim refuse points the model at LAN `ip.src` talking to that cue. The ledger can then hold the harvested LAN peer without a model `pcap_filter` call. An inverted bind still fails. Close still requires a live non-cue victim.
