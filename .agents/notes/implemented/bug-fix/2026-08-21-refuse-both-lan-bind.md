# Agent Note: Refuse both-LAN BindRelationship; c2 cannot be LAN

Status: implemented

English | [中文](2026-08-21-refuse-both-lan-bind.zh.md)

## Problem

Live lumma-r15 (`3c6d25c`) closed identity 5/5 after [stringified bind coerce](2026-08-21-bind-relationship-stringified-args.md) accepted the call. The cited conversation was Kerberos-to-DC. Bind roles were LAN victim / LAN DC as `c2`, not the victim talking to the malware cue/observation address. `whitepepper.su` and family extras did not land. The 5-slot who/where bar filled from donate on that DC conversation.

[BindRelationship](../feature/2026-08-21-bind-relationship.md) already required exactly one victim and [refused cue-as-victim](2026-08-21-refuse-cue-as-victim.md). It did not require the cited conversation to include a cue/observation address, and it accepted `c2` on a LAN DC.

## Decision

After coerce, `resolveBind` requires the cited conversation (`relationship` src/dst) to include a cue/observation address (`isCueObservationAddr`: non-LAN unicast IPv4). A both-LAN conversation (workstation↔DC Kerberos/SAMR/LDAP) is unbound. The deny text is `unbound: cite the LAN host talking to the cue/observation address, not a LAN DC/AD service.` It does not invent a malware C2 IP.

Role `c2` cannot be a LAN address (`isLanIpv4`). Tokens are not swapped. [Cue-as-victim](2026-08-21-refuse-cue-as-victim.md) stays refused.

A both-LAN deny does not issue a hunt. [other-end](2026-08-21-other-end-hunt-on-cue-victim.md) remains only for cue-as-victim on a conversation that includes a cue. Donate, who/where projection, and garbage-user reject stay. No new identity slots.

[BindRelationship](../feature/2026-08-21-bind-relationship.md) still owns bind-before-close. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET cue, and LAN DC.

## Alternatives considered

**Accept Kerberos-to-DC as the cited conversation when the cue is a malware C2.** Rejected: that binds C2 to a LAN DC/AD service.

**Silently swap the LAN DC to `infra` and the cue to `c2`.** Rejected: tokens are not swapped. Refuse the bind.

**Invent the malware C2 IP in the deny, hunt, prompt, or tests.** Rejected: the model must cite the conversation that already includes the cue.

**Issue `other-end` or another hunt that invents a C2 after a both-LAN deny.** Rejected: `other-end` remains only for cue-as-victim.

**Teach only the methodology prompt or the tool description.** Rejected: lumma-r15 would still accept the DC conversation.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET cue, and LAN DC.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET cue (`198.51.100.80`), and LAN DC (`10.0.10.3`). `10.0.10.2` ↔ `10.0.10.3` with `c2=10.0.10.3` is denied and does not issue `other-end`. `10.0.10.2` ↔ `198.51.100.80` with victim=`10.0.10.2` / c2=`198.51.100.80` is accepted. Cue-as-victim still names the other-end hunt. Stringified `endpoints` plus `dport` `"443"` still coerce then accept on the victim↔cue conversation. Identity donate tests stay green. `packages/analyst/investigation/tests/investigation.spec.ts` denies the both-LAN call through `tools.execute` without recording `other-end`.

## Consequences

A workstation↔DC bind stays unbound. A LAN `c2` stays unbound. A live LAN-victim / cue-c2 bind still closes. `other-end` still fires only for cue-as-victim.
