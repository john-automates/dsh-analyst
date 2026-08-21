# Agent Note: Deny write/edit of case-root close files

Status: implemented

English | [中文](2026-08-21-deny-close-file-writes.zh.md)

## Problem

Live lumma-r5 (`61894ac`) bound the cited conversation correctly (LAN victim / external c2). The ledger held all five gold slots. The model never called `case_report`. It used `write()` for case-root `report.md`. [Stringified who/where](2026-08-21-case-report-stringified-who-where.md) coerce and [victim-row projection](2026-08-21-case-report-victim-row-entity-id.md) never ran. Accepted who/where stayed empty. The close bar was 0/5.

`isWritablePath` still lists case-root `report.md` as a permitted write target. Evidence policy only denies evidence paths, so `write` / `edit` of `report.md` succeeded after a live bind and skipped the close packet.

## Decision

After BindRelationship, close is `case_report` only. `tools/pre-execute` denies `write`, `edit`, and `str_replace_editor` when the path is a case-root close file (`report.md`, `report.txt`, `case_report.md`). The deny text is `close with case_report after BindRelationship.` `report.md` is not parsed into who/where. `notes/` stays writable. Unbound `case_report` still returns `unbound: assign victim vs c2 on the cited conversation.` Inverted victim/c2 is refused. Tokens are not swapped.

Scout, leftover-report harvest bans, and new evals stay out of this change. Tests use a synthetic LAN client and a TEST-NET peer.

## Alternatives considered

**Silently parse `report.md` into who/where.** Rejected: that hides a skipped `case_report` and invents slots the close packet never recorded.

**Change only the methodology prompt.** Rejected: the model can still write `report.md` after a live bind.

**Deny write/edit of `report.md` only while unbound.** Rejected: the live miss wrote `report.md` after the bind. The close file is never a close path.

**Ban leftover-report harvest in the same change.** Rejected: that is a different leftover-file knob. This knob is write/edit of the close file.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP and a TEST-NET peer.

## Testing

`packages/analyst/investigation/tests/policy.spec.ts` denies `write` / `edit` of case-root `report.md` and similar close files with `CLOSE_FILE_REASON`, and still allows `notes/`. `packages/analyst/investigation/tests/investigation.spec.ts` records a synthetic bind (`10.0.10.2` victim / `198.51.100.80` c2), denies `write(report.md)` and `edit(report.md)`, then closes with `case_report`. Unbound and inverted `case_report` stay denied.

## Consequences

A live bind plus `write(report.md)` fails with the close-file reason. `case_report` after that bind still writes the 5W1H packet. Unbound and inverted closes still fail with the unbound reason. A leftover `report.md` on disk is not a close packet.
