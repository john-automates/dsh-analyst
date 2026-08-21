# Agent Note: DC-only MAC is exclusive non-victim talking-IP

Status: implemented

English | [中文](2026-08-21-dc-only-mac-is-exclusive-non-victim-talking-ip.zh.md)

## Problem

Live fake-software r5 (`mta-2025-01-22`) bound the cited conversation correctly (LAN victim / non-LAN C2). `case_report` accepted structured who/where. User, hostname, and ip persisted. MAC failed.

Submitted where had a mac. Persisted who/where had no mac. That submitted MAC was ledger-stuck on the DC (first harvest/donate stamped DC `evidence_id` / `entity_id`). `completeAcceptedSlot` stripped it as not victim-IP-evidenced. The omitted-mac fill also returned empty. The real DC/gateway NIC stayed off.

[Keep submitted victim MAC unless DC-only](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md) already said keep unless DC/gateway-only. Its DC-only test required a positive same-line talking-IP (`eth.src` + `ip.src` victim) or a victim-IP-scoped `eth.src` dump. [Complete omitted victim-row mac and user](2026-08-21-complete-omitted-victim-mac-user.md) used the same positive test. Absence of those frames was treated as DC-only, so a sticky first-donate hid a NIC that talking-IP never proved DC-only.

## Decision

After a live bind, persist a submitted mac on victim who/where unless talking-IP frames source that MAC only from a non-victim (never as `eth.src` from the bound victim IP; never the NIC of that victim). Do not use ledger `evidence_id`, `entity_id`, or first-donate as the ownership test. Absence of talking-IP evidence is not DC-only.

Fill omitted mac the same way: persist the unique ledger MAC that is not DC/gateway-only. A sticky DC stamp does not hide a NIC that is not proven DC-only. If several MACs are equally unproven, persist none.

A submitted or omitted DC/gateway NIC that only talks from the DC/idle host stays off. Do not drop ip, hostname, user, or `full_name`. Do not replace bound victim ip with a model-offered ip. Harvest stamps, bind accept/deny, and C2-domain persist stay.

`offeredMacEvidencedOnVictim` / `omittedMacEvidencedOnVictim` use talking-IP exclusivity. `evidencedOnVictimIp` still owns donate and victim-IP-scoped dump affiliation.

[Keep submitted victim MAC unless DC-only](2026-08-21-keep-submitted-victim-mac-unless-dc-only.md) still keeps a submitted mac unless DC-only; this note owns the DC-only test. [Complete omitted victim-row mac and user](2026-08-21-complete-omitted-victim-mac-user.md) still fills omitted mac; uniqueness among unproven MACs stays the stray guard. Cue-as-victim stays refused. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, idle or DC LAN row, and synthetic `CLIENT_MAC` vs DC/gateway `DISTRACTOR_MAC`.

## Alternatives considered

**Keep requiring a positive victim-IP talking line or victim-IP-scoped dump to persist a submitted or omitted MAC.** Rejected: a DC-stuck client NIC with no victim-IP dump is stripped even though talking-IP never sourced it only from a non-victim.

**Treat ledger `evidence_id`, `entity_id`, or first-donate as DC-only.** Rejected: those stamps are harvest/donate affiliation, not talking-IP ownership.

**Treat absence of talking-IP evidence as DC-only.** Rejected: DC-only is exclusive non-victim talking-IP. Missing frames do not prove a NIC is the DC or gateway.

**Copy every omitted ledger MAC onto the victim row.** Rejected: several equally unproven MACs must not invent one from the pile.

**Change harvest stamps, bind accept/deny, donate, or C2-domain persist so a sticky DC row becomes the victim.** Rejected: this knob is accepted who/where persist after a live bind.

**Drop ip, hostname, user, or `full_name`, or copy a model-offered IP over the bound victim ip.** Rejected: those slots already persist.

**Bake gold identities into harness code or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, and synthetic `CLIENT_MAC` / `DISTRACTOR_MAC`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), `CLIENT_MAC`, and `DISTRACTOR_MAC`. After a live bind, a client MAC first-donated to the DC (`evidence_id` and `entity_id` = idle/DC) persists on submitted where and omitted who when evidence text has only a DC talking frame, conversations, or is empty. A submitted DC MAC that talks only from the idle/DC IP stays off. Several equally unproven MACs persist none on omitted who. User, hostname, and ip still persist. Donate, restamp, uniqueness, and DC-NIC-off coverage stay. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the unique omitted client MAC through `bind_relationship` then `case_report` when no talking-IP frames exist.

## Consequences

A live bind plus a submitted or unique omitted client MAC writes that mac even when a sticky DC donate left the projected row empty and evidence text has no victim-IP `eth.src` line. A DC/gateway NIC that only talks from the DC/idle host still stays off. Several unproven MACs still persist none. Bound victim ip stays. Submitted user/hostname/`full_name` and donated slots stay. Harvest stamps and bind accept/deny stay.
