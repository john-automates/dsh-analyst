# Agent Note: Coerce victim-row handle strings in case_report who/where

Status: implemented

English | [中文](2026-08-21-case-report-victim-handle-strings.zh.md)

## Problem

Live lumma-r6 (`3880fd9`) bound the cited conversation twice, both correct (LAN victim / external c2). PR16 denied two `report.md` writes. Then three `case_report` calls, all denied unbound. `who`/`where` arrived as free-text strings, not `entity_id` objects: first `gwyatt (Gabriel Wyatt)` / `10.1.21.58 (desktop-es9f3ml)`, then `gwyatt` / `10.1.21.58`. No `investigation/report` packet was written.

[Handle projection](2026-08-21-case-report-victim-row-entity-id.md) and [JSON-object coerce](2026-08-21-case-report-stringified-who-where.md) never ran because `caseReportDenyReason` still does `if (typeof value === 'string') return UNBOUND_REASON` after `coerceIdentitySlotArg`, which only JSON-parses strings that start with `{`.

## Decision

After a live bind, `caseReportDenyReason` coerces a `who`/`where` string into `{ entity_id: victim.addr }` when every identity token in it is a victim-row handle (bound victim IP, or a ledger user / full_name / hostname / MAC that donates to that victim or is evidenced on that victim). The existing victim-row projection then writes the packet. JSON-object-string coerce stays first. No live bind still denies. A string that names the c2, a distractor, another IPv4, or unmatched identity tokens stays unbound. Tokens are not swapped. `report.md` is not parsed. Slots are not invented. Labeled field names, sentence wrappers, multi-word `full_name` matching, and handles evidenced on the victim without donate are [labeled handle strings](2026-08-21-case-report-labeled-victim-handle-strings.md). A leftover DC/gateway-only MAC is [dropped](2026-08-21-drop-dc-only-mac-from-handle-string-coerce.md).

Scout, leftover-report bans, harvest affiliation, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and handles on that victim row.

## Alternatives considered

**Teach the model in the prompt to send object who/where.** Rejected: the live calls already sent victim-row handle strings after a correct bind; the deny discarded them as free text.

**Parse `report.md` into who/where.** Rejected: that is a different knob. Close-file writes stay denied; this knob is the `case_report` string.

**Silently swap C2 and victim tokens when the pair is inverted.** Rejected: that is the archived rewrite. Inversion still fails unbound.

**Coerce any string after a live bind to the victim.** Rejected: a string that names the c2, a distractor, another IPv4, or unmatched prose must stay unbound.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP plus handles on that row.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` binds a synthetic LAN client (`10.0.10.2`) to a TEST-NET peer (`198.51.100.80`) and puts `lan-user` / `Lan User` / `lan-host` on that victim row. After that bind, `case_report` with who/where as victim-handle strings (user, `user (Full Name)`, victim IP, `IP (HOSTNAME)`) is allowed, and who/where project to the victim row. A C2 IP string, a distractor user string, and unmatched prose stay unbound. No live bind still denies. `packages/analyst/analyst-tools/tests/tools.spec.ts` executes the same handle-string `case_report` through `bind_relationship` then `case_report` and records `investigation/report` with the victim address and donated row fields.

## Consequences

A live bind plus a victim-row handle string writes the 5W1H packet. The account name is not stored as `entity_id`. Unbound and inverted closes still fail with the unbound reason. JSON-object-string who/where still coerce first.
