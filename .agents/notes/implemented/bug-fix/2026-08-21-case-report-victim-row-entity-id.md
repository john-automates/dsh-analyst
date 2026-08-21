# Agent Note: Project case_report who/where from the victim row

Status: implemented

English | [中文](2026-08-21-case-report-victim-row-entity-id.zh.md)

## Problem

Live lumma-r3 (`aa1c361`) bound the cited conversation correctly (LAN victim / external c2, `because` cited the conversation). The first `case_report` was denied unbound, which is required. After the live bind, the second `case_report` was still denied unbound: `who.entity_id` was the user account on the victim row, while `where.entity_id` was the victim address. No `investigation/report` packet was written. Tokens were not swapped.

`caseReportDenyReason` compared `who`/`where`.`entity_id` to the bound victim address only. A user, hostname, MAC, or full_name on that row was treated as a foreign entity id. [BindRelationship](../feature/2026-08-21-bind-relationship.md) already projects who/where from the victim row after a live bind; the deny blocked that projection.

## Decision

After a live bind with exactly one victim, `who.entity_id` and `where.entity_id` may be the bound victim address or a victim-row handle (user, hostname, MAC, or full_name). Those handles are not entity ids. `projectCaseReport` still persists `entity_id` as the victim address and fills donated row fields. A non-victim conversation endpoint or another IPv4 stays unbound. Free-text who/where stay unbound. No live bind still denies. Inverted victim/c2 is refused. Tokens are not swapped.

Scout, leftover-report bans, harvest affiliation, and new evals stay out of this change. Tests use a synthetic LAN client, TEST-NET peer, and a user on that victim row.

## Alternatives considered

**Keep `entity_id ===` the victim address as the only accept path.** Rejected: the live close sent the account name in `who.entity_id` after a correct bind and never wrote a report.

**Silently swap C2 and victim tokens when the pair is inverted.** Rejected: that is the archived rewrite. Inversion still fails unbound.

**Teach the model in the prompt to put the victim address in `who.entity_id`.** Rejected: the first unbound deny already taught the bind; the second deny was the handle check.

**Affiliate harvested users onto the victim in the same change.** Rejected: names still donate only with an explicit victim `entity_id` or a sourced MAC. This knob is the close deny.

**Bake gold identities into prompts or tests, invent evals, or touch scout.** Rejected: the fixture is a synthetic LAN IP plus a user on that row.

## Testing

`packages/analyst/investigation/tests/bind.spec.ts` binds a synthetic LAN client (`10.0.10.2`) to a TEST-NET peer and puts `lan-user` on that victim row. `case_report` with `who.entity_id` = that username is denied while unbound, denied when `who.entity_id` is the c2 address, and closes with `who`/`where`.`entity_id` = the victim address after the bind. `packages/analyst/analyst-tools/tests/tools.spec.ts` executes the same fixture through `bind_relationship` then `case_report` and records `investigation/report` with the victim address and donated user.

## Consequences

A live bind plus a victim-row user handle writes the 5W1H packet. The account name is not stored as `entity_id`. Unbound and inverted closes still fail with the unbound reason. Hostname, user, and full_name still enter the slot only by donation, not by rewrite.
