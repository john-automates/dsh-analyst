# Agent Note: Keep submitted victim MAC unless DC-only

Status: implemented

English | [中文](2026-08-21-keep-submitted-victim-mac-unless-dc-only.zh.md)

## Problem

Live fake-software r2 (`mta-2025-01-22`) bound the cited conversation correctly (LAN victim / non-LAN C2). [Keep submitted victim-row identities](2026-08-21-keep-submitted-victim-row-identities.md) persisted a submitted user. The model also submitted the victim MAC on `case_report`. Accepted who/where dropped `mac`.

The identity ledger had donated that MAC to the DC (sticky DC `evidence_id`), so the projected victim row had no donated mac. `completeAcceptedSlot` then skipped every model-offered `ip`/`mac`. A later DC MAC the model might offer stayed off.

DC-scoped stay-off means a MAC that only appears on DC/gateway frames, not a MAC first harvested under a DC hunt subject (or first donated to the DC) that the model then submits on the victim entity. A sticky DC donate must not override a submitted victim MAC.

## Decision

When projecting or remapping who/where onto the bound victim entity, keep a submitted `mac` if the model offered that key, the projected row has no donated value, and that MAC is not DC/gateway-only. Persist that mac on accepted who/where. Do not invent a MAC the model never submitted.

A MAC is DC/gateway-only when it never appears as `eth.src` on the bound victim IP and never appears in a victim-IP-scoped `eth.src` dump. Talking-IP / `ipsEvidencingMac` / `evidencedOnVictimIp` / victim-IP-scoped dump helpers decide that. A sticky DC `evidence_id` is not DC-only when victim-IP frames also source that MAC, or when the model submitted it on the victim close and those helpers show it is not DC-only.

A model-offered IP does not replace the bound victim ip. Submitted user/hostname/`full_name` still persist under [keep submitted victim-row identities](2026-08-21-keep-submitted-victim-row-identities.md). Donated ip/hostname/user/`full_name` already on the row stay.

The hole is the empty-`projected[key]` branch in `completeAcceptedSlot` — the `ip`/`mac` continue. IP stay remains: do not copy a model-offered non-victim IP over the bound victim ip.

[Persist omitted victim-row keys](2026-08-21-persist-projected-victim-slot.md) still fills omitted keys from the row. [Overwrite of a DC/peer first stamp](2026-08-21-overwrite-dc-mac-stamp-on-victim-ip-hunt.md) still owns restamp. Cue-as-victim stays refused. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, idle or DC LAN row, and synthetic `CLIENT_MAC` vs DC/gateway `DISTRACTOR_MAC`.

## Alternatives considered

**Keep skipping every model-offered `mac`.** Rejected: remap onto the victim entity wipes a submitted victim MAC after a sticky DC donate.

**Copy every model-offered MAC.** Rejected: a DC or gateway MAC that never appears as `eth.src` on the victim IP or in a victim-IP-scoped dump must stay off.

**Treat a sticky DC `evidence_id` as DC-only even when victim-IP frames source that MAC.** Rejected: DC-scoped stay-off is frame scope, not first hunt subject or first donate.

**Invent a MAC when the model omits the key and the row did not donate.** Rejected: slots the model never submitted are not invented.

**Copy a model-offered non-victim IP over the bound victim ip.** Rejected: IP stay keeps the bound victim address.

**Drop submitted user/hostname/`full_name` or donated ip/hostname/user/`full_name` when keeping a submitted mac.** Rejected: those slots already persist.

**Bake gold identities into harness code or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, and synthetic `CLIENT_MAC` / `DISTRACTOR_MAC`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), `CLIENT_MAC`, and `DISTRACTOR_MAC`. After a live bind, who/where that submit `CLIENT_MAC` (ledger first donated it to the DC; victim-IP frames also source it) persist `CLIENT_MAC`. A submitted DC-only `DISTRACTOR_MAC` stays off. Submitted user/hostname/`full_name` still persist. An omitted mac is not invented. A model-offered other IP does not replace the bound victim ip. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same submitted-mac close through `bind_relationship` then `case_report`.

## Consequences

A live bind plus a submitted victim MAC writes that mac even when a sticky DC donate left the projected row empty. A DC/gateway-only MAC still stays off. An omitted mac is still not invented. Bound victim ip stays. Submitted user/hostname/`full_name` and donated slots stay.
