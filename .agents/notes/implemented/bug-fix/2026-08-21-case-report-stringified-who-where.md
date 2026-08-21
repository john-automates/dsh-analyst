# Agent Note: Coerce stringified case_report who/where into objects

Status: implemented

English | [中文](2026-08-21-case-report-stringified-who-where.zh.md)

## Problem

Live lumma-r4 (`59ccfdb`) bound the cited conversation correctly (LAN victim / external c2). After that bind, two `case_report` calls sent `who` and `where` as JSON object strings (`{"entity_id":…}`) from Hermes XML parameter text. Both returned unbound. No `investigation/report` packet was written. The ledger already held the victim-row identities.

[Victim-row entity_id](2026-08-21-case-report-victim-row-entity-id.md) accepts a user handle on an object slot. `caseReportDenyReason` still treated any string `who`/`where` as free text. XML recovery stores each `<parameter>` value as a string, so an object parameter arrives as JSON text. `tools/pre-execute` runs that deny before `defineTool` validates arguments.

## Decision

`caseReportDenyReason` coerces a `who`/`where` value that is a JSON object string into that object before the free-text check. A live bind can then project `who.entity_id` from a victim-row user handle. The `case_report` schema accepts an object or a string so those arguments reach the deny instead of `INVALID_ARGS`. A string that is not a JSON object stays free text and remains unbound. No live bind still denies. Inverted victim/c2 is refused. Tokens are not swapped.

Scout, leftover-report bans, harvest affiliation, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and a user on that victim row.

## Alternatives considered

**Parse JSON object parameters in llm-pi-ai XML recovery.** Rejected: that widens recovery for every tool, and a native JSON-string `who`/`where` still dies at the bind check. The required close test goes through `tools.execute`, not XML recovery.

**Coerce only in analyst-tools `case_report` execute.** Rejected: `tools/pre-execute` calls `caseReportDenyReason` on the raw arguments first, so the same string still returns unbound.

**Teach the model in the prompt to send object who/where.** Rejected: the live calls already sent `entity_id` inside JSON text; the deny discarded it as free text.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP plus a user on that row.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` binds a synthetic LAN client (`10.0.10.2`) to a TEST-NET peer and puts `lan-user` on that victim row. `who`/`where` as `JSON.stringify({ entity_id })` is denied while unbound, denied when `entity_id` is the c2 address, and allowed after the bind. A non-JSON string stays unbound. `packages/analyst/analyst-tools/tests/tools.spec.ts` executes the same JSON-string `case_report` through `bind_relationship` then `case_report` and records `investigation/report` with the victim address and donated user.

## Consequences

A live bind plus XML-stringified or JSON-string who/where writes the 5W1H packet when `entity_id` is the victim address or a victim-row handle. Free-text who/where still fail unbound. Unbound and inverted closes still fail with the unbound reason.
