# Agent Note: Fold sibling identity keys into omitted case_report who/where

Status: implemented

English | [中文](2026-08-21-fold-sibling-identity-keys-into-omitted-who-where.zh.md)

## Problem

Live fake-software r8 (`mta-2025-01-22` on `4b2caad`, after [locator/CIDR leftovers](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md)) bound the cited conversation correctly (LAN victim / non-LAN C2). `case_report` was accepted. Published IP / MAC / hostname passed. `user` failed. `full_name` stayed unpublished.

[Locator/CIDR leftovers](2026-08-21-drop-locator-cidr-from-handle-string-coerce.md) did not fire: the accepted close omitted who/where and sent no Client / IP / located / at / on / network leftovers. The call sent sibling top-level keys `ip` / `mac` / `hostname` / `user` / `full_name`, not prose or JSON who/where. [Keep submitted victim-row identities](2026-08-21-keep-submitted-victim-row-identities.md) already keeps a submitted user when the projected row has no donated user, but `projectCaseReport` / `requireCaseReport` / `case_report` execute only passed `args.who` and `args.where` into `completeAcceptedSlot`. Sibling `SLOT_KEYS` on the same call never entered that submitted slot.

[Complete omitted victim-row mac and user](2026-08-21-complete-omitted-victim-mac-user.md) did not fill user: `omittedUserEvidencedOnVictim` requires a conversation-client stamp, and uniqueness donate stayed empty because the ledger held one human SAM plus machine accounts ending in `$`.

## Decision

After a live bind, when who and/or where are omitted, `projectCaseReport` folds sibling top-level identity keys (`ip`, `mac`, `hostname`, `user`, `full_name`) from the same `case_report` arguments into that submitted slot so `completeAcceptedSlot` sees them as submitted keys. `case_report` execute passes those sibling keys with who/where.

A submitted human user (not a machine SAM ending in `$`) is kept even when machine accounts also exist on the ledger and uniqueness would block omitted-user persist. A conversation-client stamp is not required when the model already named that human SAM. A machine SAM is not persisted as who/where user. A model-offered IP does not replace the bound victim ip. Donated ip / hostname / mac / `full_name` stay. A DC/gateway NIC stays off.

The hole is omitted who/where plus sibling `SLOT_KEYS` in `packages/analyst/investigation/src/bind.ts` and the `case_report` execute path. Harvest stamps, bind accept/deny, omitted-mac persist, DC-only MAC leftover drop, locator/CIDR wrappers, and C2-domain persist stay. Cue-as-victim stays refused. Scout, leftover-report bans, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` vs `DISTRACTOR_MAC`, `lan-user` / `Lan User`, and a synthetic machine SAM `lan-host$`.

## Alternatives considered

**Keep passing only `args.who` and `args.where` into `completeAcceptedSlot`.** Rejected: a post-bind close that names victim identity as sibling keys drops the submitted human user.

**Change omitted-user persist or uniqueness donate so a human SAM wins when machine accounts also exist.** Rejected: this knob is submitted-slot fold after a live bind. Omitted persist still requires victim-IP evidence. Uniqueness donate still counts every unaffiliated user.

**Persist a sibling machine SAM (`$`) as who/where user.** Rejected: a machine account is not a victim user.

**Replace the bound victim ip with a model-offered sibling ip.** Rejected: donated victim ip stays.

**Treat a present who/where object or handle string as omitted so siblings overwrite it.** Rejected: an existing object or handle-string close still works.

**Advertise sibling keys as required schema fields, change harvest stamps, bind accept/deny, omitted-mac persist, DC-only MAC leftover drop, locator/CIDR wrappers, or C2-domain persist.** Rejected: this knob is omitted who/where fold on the accepted packet.

**Bake gold identities into harness code or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN client, TEST-NET C2, idle or DC LAN row, synthetic `CLIENT_MAC` / `DISTRACTOR_MAC`, `lan-user` / `Lan User`, and `lan-host$`.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` uses a synthetic LAN client (`10.0.10.2`), TEST-NET C2 (`198.51.100.80`), idle or DC row (`10.0.10.3`), `CLIENT_MAC`, `DISTRACTOR_MAC`, `lan-user` / `Lan User`, and machine SAM `lan-host$`. After a live bind, `case_report` that omits who/where and sends sibling top-level `ip` / `mac` / `hostname` / `user` / `full_name` (human `lan-user`) persists `lan-user` on who/where even when the ledger also has `lan-host$` and another unaffiliated user and has no conversation-client stamp. A sibling machine-SAM user is not persisted. ip / mac / hostname / `full_name` stay. `DISTRACTOR_MAC` stays off. A model-offered sibling ip does not replace the bound victim ip. An existing who/where object or handle-string close still accepts. Cue-as-victim stays refused. `packages/analyst/analyst-tools/tests/tools.spec.ts` records the same sibling-key close through `bind_relationship` then `case_report` execute.

## Consequences

A live bind plus an omitted who/where close that names victim identity as sibling top-level keys writes those keys onto accepted who/where, including a submitted human user when machine accounts also exist. A machine SAM still stays off. A DC/gateway NIC still stays off. Donated ip / hostname / mac / `full_name` stay. Cue-as-victim stays refused.
